FROM instructure/node:12

ENV APP_HOME /usr/src/app

USER root

RUN mkdir -p $APP_HOME
COPY package.json yarn.lock $APP_HOME/
WORKDIR $APP_HOME
RUN yarn install
RUN chown -R docker:docker $APP_HOME
COPY . $APP_HOME
RUN ["bash", "-c", "shopt -s extglob dotglob\nchown -R docker:docker $APP_HOME/!(node_modules)"]

USER docker
