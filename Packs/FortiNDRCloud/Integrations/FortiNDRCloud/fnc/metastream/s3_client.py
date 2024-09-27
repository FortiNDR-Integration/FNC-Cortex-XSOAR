import gzip
import json
import sys
from typing import Iterator, List

import boto3
import botocore.client
import botocore.config

from fnc.global_variables import (
    METASTREAM_MAX_CHUNK_SIZE,
    METASTREAM_SUPPORTED_EVENT_TYPES,
)


class MetastreamContext:
    def __init__(self):
        self._checkpoint = ''
        self._history = {}
        self.file_downloads = 0
        self.api_calls = 0

    def _is_full_history(self, history: dict = None):
        return any([i in history for i in METASTREAM_SUPPORTED_EVENT_TYPES])

    def update_history(self, event_type: str = None, history: dict = None):
        if self._is_full_history(history=history):
            self._history = history
        elif not event_type:
            for event_type in METASTREAM_SUPPORTED_EVENT_TYPES:
                self.update_history(event_type=event_type, history=history)
        elif history:
            self._history[event_type] = history.copy()

    def get_history(self, event_type: str = None):
        if not event_type:
            return self._history

        elif event_type not in self._history:
            return None

        return self._history.get(event_type)

    def update_checkpoint(self, checkpoint: str):
        self._checkpoint = checkpoint

    def get_checkpoint(self):
        return self._checkpoint

    def file_downloads_incr(self):
        self.file_downloads += 1

    def api_calls_incr(self):
        self.api_calls += 1


class S3Client:
    def __init__(self, bucket: str, access_key: str, secret_key: str, user_agent_extra: str, client: botocore.client.BaseClient = None,
                 context: MetastreamContext = None):
        """
        S3Client provides a context manager for _S3Client.  Provides higher level methods for S3.

        :param bucket: S3 bucket
        :param access_key: aws access key
        :param secret_key: aws secret access key
        :param user_agent_extra: appends to user-agent
        :param client: optional boto3 client
        :param context: optional context for exporting metrics
        """
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key
        self.user_agent_extra = user_agent_extra
        self.client = client
        self.context = context

    def __enter__(self):
        self.client = _S3Client(self.bucket, self.access_key, self.secret_key,
                                self.user_agent_extra, self.client, self.context)
        return self.client

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
        # older version of boto3 in splunk cloud doesn't have close() method.
        # self.client.client.close()


class _S3Client:
    S3_MAX_KEYS = 1000

    def __init__(self, bucket: str, access_key: str, secret_key: str, user_agent_extra: str, client, context: MetastreamContext):
        self.bucket = bucket
        self.context = context or MetastreamContext()
        if client is not None:
            self.client = client
        else:
            config = botocore.config.Config(user_agent_extra=user_agent_extra)
            self.client = boto3.client(
                's3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, config=config)

    def fetch_common_prefixes(self, prefix: str) -> Iterator[List[str]]:
        """
        A generator function that yields common prefix found after the given prefix.

        :param prefix: s3 bucket key prefix
        """
        if not prefix.endswith('/'):
            prefix += '/'
        self.context.api_calls_incr()
        obj = self.client.list_objects_v2(
            Bucket=self.bucket,
            Delimiter="/",
            Prefix=prefix,
            MaxKeys=self.S3_MAX_KEYS
        )
        common_prefixes = obj.get('CommonPrefixes') or []
        for prefix in common_prefixes:
            yield prefix.get('Prefix')

        while obj.get('IsTruncated'):
            self.context.api_calls_incr()
            obj = self.client.list_objects_v2(
                Bucket=self.bucket,
                Delimiter="/",
                Prefix=prefix,
                ContinuationToken=obj.get('NextContinuationToken'),
                MaxKeys=self.S3_MAX_KEYS
            )
            common_prefixes = obj.get('CommonPrefixes') or []
            for prefix in common_prefixes:
                yield prefix.get('Prefix')

    def fetch_file_objects(self, prefix: str) -> Iterator[List]:
        """
        A generator method that yields file objects found after the given key prefix.

        :param prefix: s3 bucket key prefix
        """
        self.context.api_calls_incr()
        obj = self.client.list_objects_v2(
            Bucket=self.bucket,
            Prefix=prefix,
            MaxKeys=self.S3_MAX_KEYS
        )
        contents = obj.get('Contents') or []
        for item in contents:
            yield item

        while obj.get('IsTruncated'):
            self.context.api_calls_incr()
            obj = self.client.list_objects_v2(
                Bucket=self.bucket,
                Prefix=prefix,
                ContinuationToken=obj.get('NextContinuationToken'),
                MaxKeys=self.S3_MAX_KEYS
            )
            contents = obj.get('Contents') or []
            for item in contents:
                yield item

    def fetch_gzipped_json_lines_file(self, key: str) -> Iterator[List]:
        """
        Downloads a gzipped file of `JSON Lines` format and converts it to Python.

        :param key: s3 key to a gzipped JSON Lines file
        :returns Contents of the file converted to Python
        """
        s3_object = self.client.get_object(
            Bucket=self.bucket, Key=key)['Body']
        rows = []
        total_size = 0
        with gzip.open(s3_object, "r") as f:
            for row in f:
                rows.append(json.loads(row))
                total_size += sys.getsizeof(row)
                if total_size >= METASTREAM_MAX_CHUNK_SIZE:
                    yield rows
                    rows = []
                    total_size = 0
            if rows:
                yield rows
