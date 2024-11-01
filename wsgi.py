# Import main backend application
from lv_backend_main import app


# This file provides the WSGI fork.

if __name__ == "__main__":
    app.run()
