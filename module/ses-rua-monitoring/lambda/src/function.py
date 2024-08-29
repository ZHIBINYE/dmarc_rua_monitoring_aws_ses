import json
import logging
from typing import Dict
import os
from handler import Email, DmarcReport, SlackClient
from utils import extract_zip, analysis_report, get_s3_client
from config import Config
from datetime import datetime, timedelta, timezone
from pathlib import Path

TMP_DIRECTORY = "/tmp"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
config = Config()
s3_clenit = get_s3_client(config)

def lambda_handler(event: Dict, _):
    logger.info(f"Input: {json.dumps(event)}")
    t_delta = timedelta(hours=9)
    jst = timezone(t_delta, 'JST')
    now = datetime.now(jst)
    now_ym_key = now.strftime("%Y%m") + "/"
    event_s3_info = event["Records"][0]["s3"]
    bucket = s3_clenit.get_object(Bucket=event_s3_info["bucket"]["name"], Key=event_s3_info["object"]["key"])
    body = bucket['Body'].read()
    email = Email(body.decode('utf-8'))
    if email.email_object is None:
        return {
            'message' : "email content parse failed."
        }
    
    file_list = email.save_attach_file(TMP_DIRECTORY)
    if len(file_list) == 0:
        return {
            'message' : "no found zip."
        }
    
    slackClient = SlackClient(config.slack_bot_token)
    for f in file_list:
        zip_file_list = extract_zip(f, TMP_DIRECTORY)
        if len(zip_file_list) == 0:
            continue
        
        reports: list[DmarcReport] = [DmarcReport(r) for r in analysis_report(zip_file_list)]
    
        if not exists(config.save_report_s3_bucket, now_ym_key):
            s3_clenit.put_object(Bucket=config.save_report_s3_bucket, Key=now_ym_key)
        for report in reports:
            json_path, csv_path, graph_url = upload_report_to_s3(report, now_ym_key, config)
            if not report.is_all_dmarc_pass:
                org_name = report.metadata["org_name"]
                begin = report.metadata["date_range"]["begin"]
                end = report.metadata["date_range"]["end"]
                slackClient.post_message({
                    "text": "dmarc failed mail is existed",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "dmarc failed mail is existed.report id:{}".format(report.report_id)
                            }
                        }
                    ],
                    "attachments": [{
                    "color": "#DAA038",
                    "blocks": [
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Dmarc report by provider*\n{org_name}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*data(from - to)*\n{begin} - {end}"
                                }
                            ]
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*count*\n{len(report.records)}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*report download*\n<https://ap-northeast-1.console.aws.amazon.com/s3/object/{config.save_report_s3_bucket}?region=ap-northeast-1&bucketType=general&prefix={now_ym_key}{Path(csv_path).name}|csv report download>\n<https://ap-northeast-1.console.aws.amazon.com/s3/object/{config.save_report_s3_bucket}?region=ap-northeast-1&bucketType=general&prefix={now_ym_key}{Path(json_path).name}|json report download>"
                                }
                            ]
                        },
                        {
                            "type": "image",
                            "title": {
                                "type": "plain_text",
                                "text": report.report_id
                            },
                            "image_url": graph_url,
                            "alt_text": "dmarc report result"
                        }
                    ]
                }]
                }, config.slack_channel)
    return {
        'message' : "success"
    }

def upload_report_to_s3(report: DmarcReport, now_ym_key: str, config: Config):
    def _upload_to_s3_and_get_url(file: str, key: str, config: Config):
        s3_clenit.upload_file(Filename=file, Bucket=config.save_report_s3_bucket, Key=key + Path(file).name)
        return s3_clenit.generate_presigned_url(
            "get_object",
            Params={"Bucket": config.save_report_s3_bucket, "Key":key + Path(file).name},
            ExpiresIn=config.image_presigned_url_expiration,
        )

    report_paths = report.export_report(TMP_DIRECTORY)
    json_path = report_paths["json_path"]
    csv_path = report_paths["csv_path"]
    graph_path = report_paths["graph_path"]
    s3_clenit.upload_file(Filename=json_path, Bucket=config.save_report_s3_bucket, Key=now_ym_key + Path(json_path).name)
    s3_clenit.upload_file(Filename=csv_path, Bucket=config.save_report_s3_bucket, Key=now_ym_key + Path(csv_path).name)
    graph_url = _upload_to_s3_and_get_url(graph_path, now_ym_key, config)
    os.remove(json_path)
    os.remove(csv_path)
    os.remove(graph_path)
    return json_path, csv_path, graph_url

def exists(bucket: str, key: str) -> bool:
    """
    指定した key が指定した bucket の中に存在するか

    :param bucket: (str) bucket name
    :param key: (str) key
    :return: (bool)
    """
    contents = s3_clenit.list_objects(Prefix=key, Bucket=bucket).get("Contents")
    if contents:
        for content in contents:
            if content.get("Key") == key:
                return True
    return False
