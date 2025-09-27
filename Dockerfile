FROM ruby:3.3-alpine

RUN apk add --no-cache \
  build-base \
  postgresql-client postgresql-dev \
  tzdata git bash \
  yaml-dev pkgconfig

RUN gem install bundler:2.4.22

WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle _2.4.22_ install
COPY . .

ENV RAILS_ENV=development
EXPOSE 3000
CMD ["bin/rails","s","-b","0.0.0.0","-p","3000"]
