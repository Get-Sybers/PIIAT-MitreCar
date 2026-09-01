-- Generated from piiat_mitrecar (store.py) at PIIAT-MitreCar commit 92798f2cb554706172c43cb486a97ce2f1156af2;
-- car submodule 1b922fe1527d956e222a99473472e594f10f610b, attack-datasources submodule 5d50f731de441eb09078623a2c29cc3420a01949; date 2026-09-01.
-- car.sql is SCHEMA-ONLY: no CAR event rows exist without evidence ingestion.
-- Regenerate: build the DB via the pipeline's own store class, then '\n'.join(sqlite3.connect(db).iterdump()).
--   e.g. python -c "from piiat_mitrecar import store; store.CarStore('car.db')"  (car.db: schema only)
--        python -c "from piiat_mitrecar.superset import SupersetStore; s=SupersetStore('superset.db'); s.seed_model()"  (superset.db: model seed)
--        then: open(out,'w').write('\n'.join(con.iterdump()))

BEGIN TRANSACTION;
CREATE TABLE "authentication" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "app_name", "method", "auth_service", "auth_target", "target_ad_domain", "decision_reason", "response_time", "fqdn", "hostname", "ad_domain", "uid", "user_role", "user_type", "user", "user_agent", "target_uid", "target_user_role", "target_user_type", "target_user");
CREATE TABLE "driver" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "fqdn", "hostname", "base_address", "image_path", "md5_hash", "sha1_hash", "sha256_hash", "module_name", "signer", "pid", "signature_valid");
CREATE TABLE "email" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "action_reason", "attachment_name", "attachment_size", "attachment_mime_type", "dest_ip", "dest_port", "dest_address", "date", "server_relay", "from", "smtp_uid", "message_links", "src_address", "src_domain", "return_address", "message_body", "subject", "src_ip", "src_port", "message_type", "to");
CREATE TABLE "file" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "creation_time", "file_name", "fqdn", "hostname", "image_path", "md5_hash", "sha1_hash", "sha256_hash", "pid", "ppid", "previous_creation_time", "signer", "user", "company", "file_path", "owner_uid", "owner", "content", "extension", "gid", "group", "link_target", "mime_type", "mode", "signature_valid", "uid");
CREATE TABLE "flow" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "fqdn", "hostname", "content", "dest_ip", "dest_port", "src_ip", "src_port", "start_time", "end_time", "exe", "image_path", "packet_count", "pid", "ppid", "proto_info", "user", "src_fqdn", "src_hostname", "dest_fqdn", "dest_hostname", "application_protocol", "in_bytes", "out_bytes", "network_direction", "tcp_flags", "transport_protocol", "uid");
CREATE TABLE "http" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "hostname", "request_body_bytes", "http_version", "request_body_content", "request_referrer", "requester_ip_address", "response_body_bytes", "response_body_content", "response_status_code", "url_full", "url_domain", "url_remainder", "url_scheme", "user_agent_full", "user_agent_name", "user_agent_device", "user_agent_version");
CREATE TABLE "module" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "fqdn", "hostname", "base_address", "image_path", "md5_hash", "sha1_hash", "sha256_hash", "module_path", "module_name", "pid", "signer", "tid", "signature_valid");
CREATE TABLE "process" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "fqdn", "hostname", "command_line", "exe", "image_path", "md5_hash", "sha1_hash", "sha256_hash", "parent_exe", "parent_image_path", "pid", "ppid", "sid", "signer", "user", "integrity_level", "parent_command_line", "current_working_directory", "env_vars", "access_level", "call_trace", "parent_guid", "signature_valid", "target_guid", "target_pid", "target_address", "target_name", "uid");
CREATE TABLE "registry" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "fqdn", "hostname", "key", "value", "data", "type", "hive", "image_path", "pid", "user", "new_content");
CREATE TABLE "service" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "fqdn", "hostname", "user", "command_line", "exe", "image_path", "name", "pid", "ppid", "uid");
CREATE TABLE "socket" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "pid", "image_path", "success", "family", "protocol", "local_address", "local_port", "remote_port", "remote_address", "local_path");
CREATE TABLE "thread" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "hostname", "src_pid", "src_tid", "tgt_pid", "tgt_tid", "stack_base", "stack_limit", "start_address", "user", "user_stack_base", "user_stack_limit", "start_function", "start_module", "start_module_name", "uid");
CREATE TABLE "user_session" (event_id INTEGER PRIMARY KEY, "timestamp", "car_action", "guid", "owning_guid", "link_confidence", "source_artefact", "source_host", "native", "dest_ip", "dest_port", "hostname", "login_id", "src_ip", "src_port", "user", "login_type", "uid", "login_successful");
CREATE INDEX "ix_authentication_guid" ON "authentication" (guid);
CREATE INDEX "ix_authentication_ts" ON "authentication" (timestamp);
CREATE INDEX "ix_driver_guid" ON "driver" (guid);
CREATE INDEX "ix_driver_ts" ON "driver" (timestamp);
CREATE INDEX "ix_email_guid" ON "email" (guid);
CREATE INDEX "ix_email_ts" ON "email" (timestamp);
CREATE INDEX "ix_file_guid" ON "file" (guid);
CREATE INDEX "ix_file_ts" ON "file" (timestamp);
CREATE INDEX "ix_flow_guid" ON "flow" (guid);
CREATE INDEX "ix_flow_ts" ON "flow" (timestamp);
CREATE INDEX "ix_http_guid" ON "http" (guid);
CREATE INDEX "ix_http_ts" ON "http" (timestamp);
CREATE INDEX "ix_module_guid" ON "module" (guid);
CREATE INDEX "ix_module_ts" ON "module" (timestamp);
CREATE INDEX "ix_process_guid" ON "process" (guid);
CREATE INDEX "ix_process_ts" ON "process" (timestamp);
CREATE INDEX "ix_registry_guid" ON "registry" (guid);
CREATE INDEX "ix_registry_ts" ON "registry" (timestamp);
CREATE INDEX "ix_service_guid" ON "service" (guid);
CREATE INDEX "ix_service_ts" ON "service" (timestamp);
CREATE INDEX "ix_socket_guid" ON "socket" (guid);
CREATE INDEX "ix_socket_ts" ON "socket" (timestamp);
CREATE INDEX "ix_thread_guid" ON "thread" (guid);
CREATE INDEX "ix_thread_ts" ON "thread" (timestamp);
CREATE INDEX "ix_user_session_guid" ON "user_session" (guid);
CREATE INDEX "ix_user_session_ts" ON "user_session" (timestamp);
COMMIT;
