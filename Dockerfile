FROM ruby:3.3-bookworm

WORKDIR /srv

COPY Gemfile Gemfile.lock ./
RUN bundle config set frozen true
RUN bundle config set without development test
RUN bundle install

COPY . ./
RUN bundle install

CMD ["ruby", "./app.rb"]
