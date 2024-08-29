import os


class Config:
    save_report_s3_bucket: str
    slack_bot_token: str
    slack_channel: str
    image_presigned_url_expiration: int
    image_presigned_url_access_key_id: str
    image_presigned_url_secret_access_key: str
    
    def __init__(self):
        # Log group name
        self.save_report_s3_bucket = os.getenv("SAVE_REPORT_S3_BUCKET")
        # Slack app bot token
        # Required scope: chat:write
        self.slack_bot_token = os.getenv("SLACK_BOT_TOKEN")
        # Slack channel
        self.slack_channel = os.getenv("SLACK_CHANNEL")
        # Number of seconds the pre-signed image URL is valid for.
        # Default: 604800 (7 days)
        self.image_presigned_url_expiration = 60 * 60 * 24 * 7
        # IAM user access key ID to access to slack image S3 bucket
        self.image_presigned_url_access_key_id = os.getenv("IMAGE_PRESIGNED_URL_ACCESS_KEY_ID")

        # IAM user secret access key to access to slack image S3 bucket
        self.image_presigned_url_secret_access_key = os.getenv("IMAGE_PRESIGNED_URL_SECRET_ACCESS_KEY")
        