# users_teams_api_example
# Local Deployment
 - Clone or download repository
 - Create a virtual environment and activate it
-- You can use various virtual environments, like virtualenvwrapper, anaconda etc.  
 - Install requirements
```sh
> pip install -r requirements.txt
```
 - run migrations
```sh
> python manage.py migrate
```
 - create superuser
```sh
> python manage.py createsuperuser
```
 - run
```sh
> python manage.py runserver
```
# Deployment
 - add __'auth_api'__ to INSTALLED_APPS in settings.py
 - add __AUTH_USER_MODEL = 'auth_api.CustomUser'__ to settings.py
 - add __url(r'^api/$', include(auth_api.urls))__ to urlpatterns in urls.py
 - add __EMAIL_BACKEND__ and __EMAIL_FROM__ to settings.py
# API endpoints
/api/login/ __(POST)__

__requires:__ email, password
__returns:__ Authorisation Token

/api/logout/ __(POST)__

deletes Authorisation token, 
__returns:__ success message

api/userdetails/ __(GET)__ 

requires: (Auth)
__returns:__ user details

api/userdetails/ __(PUT)__

__requires:__ (Auth); email or first_name or last_name
__returns:__ user details

api/reset/ __(POST)__

__requires:__ email
creates password reset token
sends e-mail to user
__returns:__ success/error

api/password/ __(POST)__

__requires:__ (Auth); new password
OR requires: email, password reset code, new password
Sets new password, removes code
__returns:__ success/error

api/invite/ __(POST)__ 

__requires:__ (Auth); team name, recipient email
Creates or retrieves an invitation link from user to team
Sends an email with code
__returns:__ invitationLink parameters

api/register/ __(POST)__

__requires:__ email, password (first name, last name, invitation code)
Creates a new user with provided information
__returns:__ created user details

api/create_team/ __(POST)__

__requires:__ (Auth); team name
Creates a new team using provided name, adds team to user teams
__returns:__ success/error

api/verify_email/ __(POST)__

__requires:__ verification code
Verifies user email, deletes verification token record
__returns:__ success/error

api/retrieve_code/ __(POST)__

__requires:__ (Auth)
__returns:__ email verification code, password reset code

# Example application:
https://users-teams-example-app.herokuapp.com
_email:_ test@user.com
_password:_ QWer!@34

# ToDo:
- Tests
- Remove invitation link from user, team when user leaves team
