from flask_restplus import Api, fields

# Import your API Views
from .bp_system import api as bp_system
from .bp_logging import api as bp_logs
from .bp_loggingExpress import api as bp_logsExpress
from .bp_calldata import api as bp_calldata
from .bp_emailData import api as bp_emailData
from .bp_cdrData import api as bp_cdrData
from .bp_collect_log4snow import api as bp_collect_log4snow
from .bp_cmDeviceStatus import api as bp_cmDeviceStatus
from .bp_tenantdata import api as bp_tenantdata
from .bp_collect_tenantdata import api as bp_collect_tenantdata
from .bp_directory import api as bp_directory

api = Api(
    title='Log Visualizer',
    version='1.0',
    description='A place to look at logs.',
)

# Application User API
bp_logs_param = api.model("Logging",
                                 {
                                     "offset_time": fields.String(description="Time of Logs to pull", required=True),
                                     "instant": fields.String(description="Pull files instantly", required=True),
                                     'applications': fields.String(description="['cucm','vvb','fin','unity','cvp','cvpvxml','pg','rtr','livedata']")})



# Add imports to API context
api.add_namespace(bp_system)
api.add_namespace(bp_logs)
api.add_namespace(bp_logsExpress)
api.add_namespace(bp_calldata)
api.add_namespace(bp_emailData)
api.add_namespace(bp_cdrData)
api.add_namespace(bp_cmDeviceStatus)
api.add_namespace(bp_collect_log4snow)
api.add_namespace(bp_collect_tenantdata)
api.add_namespace(bp_tenantdata)
api.add_namespace(bp_directory)
