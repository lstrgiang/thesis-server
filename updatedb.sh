#today=`date '+%Y_%m_%d__%H_%M_%S'`;
#filename="/home/el/myfile/$today"
#pg_dump thesis_jwt_auth > $filename
dropdb --if-exists thesis_jwt_auth
dropdb --if-exists thesis_jwt_auth_test
createdb thesis_jwt_auth
createdb thesis_jwt_auth_test
python manage.py create_db
python manage.py db init
python manage.py db migrate
