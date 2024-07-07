# frozen_string_literal: true

require 'bundler/setup'
require 'securerandom'
Bundler.require(:default)

set :bind, ENV['BIND'] || '0.0.0.0'
set :port, ENV['PORT'] || '8080'
set :server, :thin
if ENV.key?('TLS_CERTIFICATE') && ENV.key?('TLS_KEY')
  set :server_settings, {
    ssl: true,
    ssl_cert_file: ENV['TLS_CERTIFICATE'],
    # This is the compatible set from https://developers.cloudflare.com/ssl/reference/cipher-suites/recommendations/
    ssl_cipher_list: %w[
      TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    ].join(':'),
    # This is a bit of a misnomer, this is related to requiring client certificates
    ssl_disable_verify: true,
    ssl_key_file: ENV['TLS_KEY'],
    ssl_version: 'TLSv1_2',
  }
end

ACCOUNT_KEYS = Concurrent::Map.new
NONCES = Concurrent::Map.new

K8S_CLIENT = K8s::Client.in_cluster_config
CR_RESOURCE = K8S_CLIENT.api('cert-manager.io/v1').resource('certificaterequests', namespace: 'default')

ISSUER_KIND = ENV.fetch('ISSUER_KIND')
ISSUER_NAME = ENV.fetch('ISSUER_NAME')
POD_NAMESPACE = ENV.fetch('POD_NAMESPACE')

def error_response(type)
  halt 400, {
    'Content-Type' => 'application/problem+json',
  }, {
    type: type,
  }.to_json
end

def decode_and_validate_payload(body)
  contents = begin
    JSON.parse(body)
  rescue JSON::ParserError => e
    error_response 'urn:ietf:params:acme:error:malformed'
  end

  unless contents['protected']
    error_response 'urn:ietf:params:acme:error:malformed'
  end

  protected_contents = begin
    JSON.parse(Base64.urlsafe_decode64(contents['protected']))
  rescue ArgumentError, JSON::ParserError
    error_response 'urn:ietf:params:acme:error:malformed'
  end

  unless protected_contents.key?('nonce') && NONCES.delete(protected_contents['nonce'])
    error_response 'urn:ietf:params:acme:error:badNonce'
  end

  if protected_contents.key?('jwk')
    jwk = JSON::JWK.new(protected_contents['jwk'])
    return begin
      [JSON::JWT.decode(contents, jwk), jwk]
    rescue JSON::JWS::VerificationFailed
      halt 400
    end
  elsif protected_contents.key?('kid')
    jwk = ACCOUNT_KEYS[protected_contents['kid'].split('/').last]

    unless jwk
      error_response 'urn:ietf:params:acme:error:accountDoesNotExist'
    end

    return begin
      [JSON::JWT.decode(contents, jwk), jwk]
    rescue JSON::JWS::VerificationFailed
      error_response 'urn:ietf:params:acme:error:malformed'
    end
  else
    error_response 'urn:ietf:params:acme:error:malformed'
  end
end

before do
  response.headers['Replay-Nonce'] = SecureRandom.urlsafe_base64(32).tap do |nonce|
    NONCES[nonce] = Time.now
  end
end

get '/' do
  json({
    keyChange: 'key-change',
    newAccount: 'new-account',
    newOrder: 'new-order',
    newNonce: 'new-nonce',
    revokeCert: 'revoke-cert',
  }.transform_values do |path|
    File.join(request.base_url, path)
  end)
end

post '/new-account' do
  payload, key = decode_and_validate_payload(request.body.read)

  ACCOUNT_KEYS.put_if_absent(key.thumbprint, key)

  response.headers['Location'] = File.join(request.base_url, "/account/#{key.thumbprint}")

  [
    payload['onlyReturnExisting'] ? 200 : 201,
    json({
      status: 'valid',
    }),
  ]
end

get '/new-nonce' do
  204
end

post '/new-order' do
  payload, _ = decode_and_validate_payload(request.body.read)

  unless payload.key?('identifiers') && !payload['identifiers'].empty? && payload['identifiers'].all? { |i| i['type'] == 'dns'}
    error_response 'urn:ietf:params:acme:error:malformed'
  end

  id = "#{Digest::SHA2.hexdigest(payload['identifiers'].map { |i| i['value'] }.sort.join("\n"))}--#{Time.now.to_i}"

  response.headers['Location'] = File.join(request.base_url, "/orders/#{id}")

  [
    201,
    json({
      authorizations: [],
      finalize: File.join(request.base_url, "/orders/#{id}/finalize"),
      status: 'ready',
    }),
  ]
end

post '/orders/:id' do
  decode_and_validate_payload(request.body.read)

  request = CR_RESOURCE.get(params.fetch(:id))

  status = if request.status.conditions.detect { |c| c.type == 'Ready' }&.status == 'Ready'
    'ready'
  else
    'processing'
  end

  response = {
    authorizations: [],
    finalize: File.join(request.base_url, "/orders/#{params.fetch(:id)}/finalize"),
    status: status,
  }

  response[:certificate] = File.join(request.base_url, "/orders/#{params.fetch(:id)}/certificate") if status == 'ready'

  json(response)
end

post '/orders/:id/certificate' do
  decode_and_validate_payload(request.body.read)

  request = CR_RESOURCE.get(params.fetch(:id))

  Base64.urlsafe_decode64(request.status.certificate)
end

post '/orders/:id/finalize' do
  payload, _ = decode_and_validate_payload(request.body.read)

  CR_RESOURCE.create_resource(K8s::Resource.new({
    apiVersion: 'cert-manager.io/v1',
    kind: 'CertificateRequest',
    metadata: {
      name: params.fetch(:id),
      namespace: POD_NAMESPACE,
    },
    spec: {
      duration: '2160h',
      issuerRef: {
        group: 'cert-manager.io',
        kind: ISSUER_KIND,
        name: ISSUER_NAME,
      },
      request: Base64.urlsafe_encode64(OpenSSL::X509::Request.new(Base64.urlsafe_decode64(payload['csr'])).to_pem),
    },
  }))

  json({
    authorizations: [],
    finalize: File.join(request.base_url, "/orders/#{params.fetch(:id)}/finalize"),
    status: 'processing',
  })
end
