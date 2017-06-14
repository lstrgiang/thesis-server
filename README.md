## Quick Start
[![CircleCI](https://circleci.com/gh/lstrgiang/thesis-server.svg?style=svg)](https://circleci.com/gh/lstrgiang/thesis-server)
### Basics

1. Activate a virtualenv
1. Install the requirements
1. Setup database
1. Run server

### Set Environment Variables

Update *project/server/config.py*, and then run:

```sh
$ export APP_SETTINGS="project.server.config.DevelopmentConfig"
```

or

```sh
$ export APP_SETTINGS="project.server.config.ProductionConfig"
```

### Create DB

Create the databases in `psql`:

```sh
$ psql
# create database thesis_jwt_auth
# create database thesis_jwt_auth_testing
# \q
```

Create the tables and run the migrations:

```sh
$ python manage.py create_db
$ python manage.py db init
$ python manage.py db migrate
```

### Run the Application

```sh
$ python manage.py runserver
```

So access the application at the address [http://localhost:5000/](http://localhost:5000/)

> Want to specify a different port?

> ```sh
> $ python manage.py runserver -h 0.0.0.0 -p 8080
> ```

### Testing

Without coverage:

```sh
$ python manage.py test
```

With coverage:

```sh
$ python manage.py cov
```
