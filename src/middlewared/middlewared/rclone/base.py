class BaseRcloneRemote:
    name = NotImplemented
    title = NotImplemented

    buckets = False
    readonly = False

    rclone_type = NotImplemented

    credentials_schema = NotImplemented

    task_schema = []

    def __init__(self, middleware):
        self.middleware = middleware

    async def pre_save_task(self, task, credentials, verrors):
        pass

    def get_remote_extra(self, task):
        return dict()
