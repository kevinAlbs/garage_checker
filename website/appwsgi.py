import os
import sys

sys.path.insert(0, '/var/www/garage_checker/website')
os.chdir('/var/www/garage_checker/website')

import garage

# mod_wsgi expects the application to be named `application`.
# See https://flask.palletsprojects.com/en/2.1.x/deploying/mod_wsgi/
application = garage.app
