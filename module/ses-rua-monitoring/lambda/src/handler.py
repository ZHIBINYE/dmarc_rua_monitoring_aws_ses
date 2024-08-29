import logging
from email import message, message_from_string
import os
import re
import json
from typing import Dict
import xmltodict
from collections import OrderedDict
from utils import timestamp_to_human
from matplotlib import pyplot as pyp
from csv import DictWriter
from io import StringIO
import requests
from requests import HTTPError
import copy

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Email:
    email_bject: message.Message
    email_content: str

    def __init__(self, email_content: str):
        self.email_object = message_from_string(email_content)
        self.email_content = email_content
        if "dmarc=pass" not in str(self.email_object.get_all("Authentication-Results")):
            logger.warning("Impersonation mail was received.{}".format(email_content))
            self.email_object = None

    def save_attach_file(self, output: str) -> list:
        attach_file_names = []
        for part in self.email_object.walk():
            # Content_typeがmultipartの場合は実際のコンテンツはさらに中のpartにあるので読み飛ばす
            logger.debug("maintype : " + part.get_content_maintype())
            if part.get_content_maintype() == 'multipart':
                continue
            # ファイル名の取得
            attach_file_name = part.get_filename()
            logger.info("attach file name: {}".format(attach_file_name))
            # ファイル名がない場合処理しない
            if attach_file_name:
                # メールフォルダ内のfileディレクトリに添付ファイルを保存する
                attach_data = part.get_payload(decode=True)
                save_file = open(os.path.join(output, attach_file_name), 'wb')
                save_file.write(attach_data)
                save_file.close()
                attach_file_names.append(os.path.join(output, attach_file_name))
        if len(attach_file_names) == 0:
            logger.warning("no found zip.{}".format(self.email_content))
        return attach_file_names


class DmarcReport:
    """
    dmarcの文字列を解析して、dictのレポートを出力
    ps: parsedmarcのパッケージもあったですが、他のサポートが多すぎで、パッケージのサイズが大きかったです。
        lambda layerのサイズ制限を超えて、自作のものにしました。
        また、CSVのレポートは次のフォーマットにしたかったです。
        # https://mxtoolbox.com/Public/Tools/Dmarc_report_analyzer.aspx/Dmarc_report_analyzer.aspx?id=F-8267adaf-6b0f-4698-8e3c-32ad40281934
    """

    original_report: Dict
    records: list[Dict]
    metadata: Dict
    policy: Dict
    report_id: str
    is_all_dmarc_pass: bool
    WEDGEPROPS = {"edgecolor": "white", "width": 0.3}
    LABELS = ["failed", "passed"]
    xml_header_regex = re.compile(r"^<\?xml .*?>", re.MULTILINE)
    xml_schema_regex = re.compile(r"</??xs:schema.*>", re.MULTILINE)
    CSV_HEADER = ["email_provider", "domain_policy", "source_ip", "email_volume", "dmarc_pass", "dmarc_fail",
                  "dmarc_pass_rate",
                  "spf_authentication_pass", "spf_authentication_fail", "spf_alignment_pass", "spf_alignment_fail",
                  "dkim_authentication_pass", "dkim_authentication_fail", "dkim_alignment_pass", "dkim_alignment_fail"]

    def __init__(self, report_str: str) -> None:
        # Replace XML header (sometimes they are invalid)
        xml = self.xml_header_regex.sub("<?xml version=\"1.0\"?>", report_str)
        # Remove invalid schema tags
        xml = self.xml_schema_regex.sub('', xml)
        self.original_report = xmltodict.parse(report_str)["feedback"]
        self.policy = self.original_report["policy_published"]
        self.metadata = self._parse_meta_data()
        self.report_id = self.original_report["report_metadata"]["report_id"]
        if isinstance(self.original_report["record"], list):
            self.records = [self._parse_report_record(r) for r in self.original_report["record"]]
        else:
            self.records = [self._parse_report_record(self.original_report["record"])]
        dmarc_results = [r["alignment"]["dmarc"] for r in self.records]
        self.is_all_dmarc_pass = dmarc_results.count(False) == 0

    def export_report(self, output: str):
        file_name = "{}_{}_{}_to_{}".format(self.metadata["org_name"], self.report_id,
                                            self.metadata["date_range"]["begin"], self.metadata["date_range"]["end"])
        csv_path = os.path.join(output, file_name + ".csv")
        json_path = os.path.join(output, file_name + ".json")
        graph_path = os.path.join(output, file_name + ".png")
        self._append_json(json_path)
        self._append_csv(csv_path)
        self._append_grahp(graph_path)
        return {
            "csv_path": csv_path,
            "json_path": json_path,
            "graph_path": graph_path
        }

    def _append_csv(self, filename):
        csv_file_object = StringIO(newline="\n")
        writer = DictWriter(csv_file_object, self.CSV_HEADER)
        writer.writeheader()
        email_provider = self.metadata["org_name"]
        domain_policy = json.dumps(self.policy)
        ips = list(set([r["source"] for r in self.records]))
        rows = []
        for ip in ips:
            row = dict(email_provider=email_provider, domain_policy=domain_policy, source_ip=ip)
            target_ip_datas = [r for r in self.records if r["source"] == ip]
            dmarc_results = [r["alignment"]["dmarc"] for r in target_ip_datas]
            spf_auth_results = [self._spf_pass(r) for r in target_ip_datas]
            spf_alignment_results = [r["alignment"]["spf"] for r in target_ip_datas]
            dkim_auth_results = [self._dkim_pass(r) for r in target_ip_datas]
            dkim_alignment_results = [r["alignment"]["dkim"] for r in target_ip_datas]
            row["email_volume"] = len(target_ip_datas)
            row["dmarc_pass"] = dmarc_results.count(True)
            row["dmarc_fail"] = dmarc_results.count(False)
            row["dmarc_pass_rate"] = dmarc_results.count(True) // len(dmarc_results)
            row["spf_authentication_pass"] = spf_auth_results.count(True)
            row["spf_authentication_fail"] = spf_auth_results.count(False)
            row["spf_alignment_pass"] = spf_alignment_results.count(True)
            row["spf_alignment_fail"] = spf_alignment_results.count(False)
            row["dkim_authentication_pass"] = dkim_auth_results.count(True)
            row["dkim_authentication_fail"] = dkim_auth_results.count(False)
            row["dkim_alignment_pass"] = dkim_alignment_results.count(True)
            row["dkim_alignment_fail"] = dkim_alignment_results.count(False)
            rows.append(row)

        for row in rows:
            writer.writerow(row)
            csv_file_object.flush()

        csv = csv_file_object.getvalue()
        with open(filename, "a+", newline="\n", encoding="utf-8") as output:
            if output.seek(0, os.SEEK_END) != 0:
                # strip the headers from the CSV
                _, csv = csv.split("\n", 1)
                if len(csv) == 0:
                    # not appending anything, don't do any dance to
                    # append it correctly
                    return
            output.write(csv)

    def _spf_pass(self, record):
        return record["policy_evaluated"]["spf"] == "pass"

    def _dkim_pass(self, record):
        return record["policy_evaluated"]["dkim"] == "pass"

    def _append_grahp(self, filename):
        spf_auth_results = [self._spf_pass(r) for r in self.records]

        dmarc_results = [r["alignment"]["dmarc"] for r in self.records]
        dmarc = pyp.subplot(2, 3, 1)
        dmarc.pie([dmarc_results.count(False), dmarc_results.count(True)], labels=self.LABELS, autopct="%1.1f%%",
                  startangle=90,
                  wedgeprops=self.WEDGEPROPS, labeldistance=None)
        dmarc.set_title("dmarc")

        spf_alignment_results = [r["alignment"]["spf"] for r in self.records]
        spf_alignment = pyp.subplot(2, 3, 2)
        spf_alignment.pie([spf_alignment_results.count(False), spf_alignment_results.count(True)], labels=self.LABELS,
                          autopct="%1.1f%%",
                          startangle=90, wedgeprops=self.WEDGEPROPS, labeldistance=None)
        spf_alignment.set_title("spf alignment")

        spf_auth = pyp.subplot(2, 3, 5)
        spf_auth.pie([spf_auth_results.count(False), spf_auth_results.count(True)], labels=self.LABELS,
                     autopct="%1.1f%%",
                     startangle=90, wedgeprops=self.WEDGEPROPS, labeldistance=None)
        handles, labels = spf_auth.get_legend_handles_labels()
        lgd = dict(zip(labels, handles))
        spf_auth.legend(bbox_to_anchor=(-0.1, 1), loc='upper right', borderaxespad=0, fontsize=10,
                        labels=lgd.keys(), handles=lgd.values())
        spf_auth.set_title("spf auth")

        dkim_alignment_results = [r["alignment"]["dkim"] for r in self.records]
        dkim_alignment = pyp.subplot(2, 3, 3)
        dkim_alignment.pie([dkim_alignment_results.count(False), dkim_alignment_results.count(True)],
                           labels=self.LABELS, autopct="%1.1f%%",
                           startangle=90, wedgeprops=self.WEDGEPROPS, labeldistance=None)
        dkim_alignment.set_title("dkim alignment")

        dkim_auth_results = [self._dkim_pass(r) for r in self.records]
        dkim_auth = pyp.subplot(2, 3, 6)
        dkim_auth.pie([dkim_auth_results.count(False), dkim_auth_results.count(True)], labels=self.LABELS,
                      autopct="%1.1f%%",
                      startangle=90, wedgeprops=self.WEDGEPROPS, labeldistance=None)
        dkim_auth.set_title("dkim auth")

        spf_auth = pyp.subplot(2, 3, 5)

        report_graph_file = os.path.join(filename)
        pyp.savefig(report_graph_file)

    def _append_json(self, filename):
        reports = {
            "meta_data": self.metadata,
            "policy": self.policy,
            "records": self.records
        }
        with open(filename, "a+", newline="\n", encoding="utf-8") as output:
            output_json = json.dumps(reports, ensure_ascii=False, indent=2)
            if output.seek(0, os.SEEK_END) != 0:
                if len(reports) == 0:
                    # not appending anything, don't do any dance to append it
                    # correctly
                    return
                output.seek(output.tell() - 1)
                last_char = output.read(1)
                if last_char == "]":
                    # remove the trailing "\n]", leading "[\n", and replace with
                    # ",\n"
                    output.seek(output.tell() - 2)
                    output.write(",\n")
                    output_json = output_json[2:]
                else:
                    output.seek(0)
                    output.truncate()

            output.write(output_json)

    def _parse_meta_data(self):
        metadata = self.original_report["report_metadata"]
        metadata["date_range"]["begin"] = timestamp_to_human(metadata["date_range"]["begin"], "%Y%m%d%H%M%S")
        metadata["date_range"]["end"] = timestamp_to_human(metadata["date_range"]["end"], "%Y%m%d%H%M%S")
        return metadata

    def _parse_report_record(self, record) -> Dict:
        """
        Converts a record from a DMARC aggregate report into a more consistent
        format

        Args:
            record (Ordered_dict): The record to convert
        Returns:
            Ordered_dict: The converted record
        """
        record = record.copy()
        new_record = OrderedDict()
        new_record_source = record["row"]["source_ip"]
        new_record["source"] = new_record_source
        new_record["count"] = int(record["row"]["count"])
        policy_evaluated = record["row"]["policy_evaluated"].copy()
        new_policy_evaluated = OrderedDict([("disposition", "none"),
                                            ("dkim", "fail"),
                                            ("spf", "fail"),
                                            ("policy_override_reasons", [])
                                            ])
        if "disposition" in policy_evaluated:
            new_policy_evaluated["disposition"] = policy_evaluated["disposition"]
            if new_policy_evaluated["disposition"].strip().lower() == "pass":
                new_policy_evaluated["disposition"] = "none"
        if "dkim" in policy_evaluated:
            new_policy_evaluated["dkim"] = policy_evaluated["dkim"]
        if "spf" in policy_evaluated:
            new_policy_evaluated["spf"] = policy_evaluated["spf"]
        reasons = []
        spf_aligned = policy_evaluated["spf"] is not None and policy_evaluated[
            "spf"].lower() == "pass"
        dkim_aligned = policy_evaluated["dkim"] is not None and policy_evaluated[
            "dkim"].lower() == "pass"
        dmarc_aligned = spf_aligned or dkim_aligned
        new_record["alignment"] = dict()
        new_record["alignment"]["spf"] = spf_aligned
        new_record["alignment"]["dkim"] = dkim_aligned
        new_record["alignment"]["dmarc"] = dmarc_aligned
        if "reason" in policy_evaluated:
            if type(policy_evaluated["reason"]) is list:
                reasons = policy_evaluated["reason"]
            else:
                reasons = [policy_evaluated["reason"]]
        for reason in reasons:
            if "comment" not in reason:
                reason["comment"] = None
        new_policy_evaluated["policy_override_reasons"] = reasons
        new_record["policy_evaluated"] = new_policy_evaluated
        if "identities" in record:
            new_record["identifiers"] = record["identities"].copy()
        else:
            new_record["identifiers"] = record["identifiers"].copy()
        new_record["auth_results"] = OrderedDict([("dkim", []), ("spf", [])])
        if type(new_record["identifiers"]["header_from"]) is str:
            lowered_from = new_record["identifiers"]["header_from"].lower()
        else:
            lowered_from = ''
        new_record["identifiers"]["header_from"] = lowered_from
        if record["auth_results"] is not None:
            auth_results = record["auth_results"].copy()
            if "spf" not in auth_results:
                auth_results["spf"] = []
            if "dkim" not in auth_results:
                auth_results["dkim"] = []
        else:
            auth_results = new_record["auth_results"].copy()

        if not isinstance(auth_results["dkim"], list):
            auth_results["dkim"] = [auth_results["dkim"]]
        for result in auth_results["dkim"]:
            if "domain" in result and result["domain"] is not None:
                new_result = OrderedDict([("domain", result["domain"])])
                if "selector" in result and result["selector"] is not None:
                    new_result["selector"] = result["selector"]
                else:
                    new_result["selector"] = "none"
                if "result" in result and result["result"] is not None:
                    new_result["result"] = result["result"]
                else:
                    new_result["result"] = "none"
                new_record["auth_results"]["dkim"].append(new_result)

        if not isinstance(auth_results["spf"], list):
            auth_results["spf"] = [auth_results["spf"]]
        for result in auth_results["spf"]:
            if "domain" in result and result["domain"] is not None:
                new_result = OrderedDict([("domain", result["domain"])])
                if "scope" in result and result["scope"] is not None:
                    new_result["scope"] = result["scope"]
                else:
                    new_result["scope"] = "mfrom"
                if "result" in result and result["result"] is not None:
                    new_result["result"] = result["result"]
                else:
                    new_result["result"] = "none"
                new_record["auth_results"]["spf"].append(new_result)

        if "envelope_from" not in new_record["identifiers"]:
            envelope_from = None
            if len(auth_results["spf"]) > 0:
                spf_result = auth_results["spf"][-1]
                if "domain" in spf_result:
                    envelope_from = spf_result["domain"]
            if envelope_from is not None:
                envelope_from = str(envelope_from).lower()
            new_record["identifiers"]["envelope_from"] = envelope_from

        elif new_record["identifiers"]["envelope_from"] is None:
            if len(auth_results["spf"]) > 0:
                envelope_from = new_record["auth_results"]["spf"][-1]["domain"]
                if envelope_from is not None:
                    envelope_from = str(envelope_from).lower()
                new_record["identifiers"]["envelope_from"] = envelope_from

        envelope_to = None
        if "envelope_to" in new_record["identifiers"]:
            envelope_to = new_record["identifiers"]["envelope_to"]
            del new_record["identifiers"]["envelope_to"]

        new_record["identifiers"]["envelope_to"] = envelope_to

        return new_record

class SlackClient:
    def __init__(self, oauth_token):
        self.oauth_token = oauth_token

    def post_message(self, message, channel):
        url = "https://slack.com/api/chat.postMessage"
        payload = copy.deepcopy(message)
        payload["channel"] = channel
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "Authorization": f"Bearer {self.oauth_token}",
        }
        logger.info(payload)
        res = requests.post(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        try:
            res.raise_for_status()
            logger.info(res.json())
            return res.json()
        except HTTPError as e:
            logger.error(f"Request failed: status={e.response.status_code}, body=${e.response.text}")
            raise