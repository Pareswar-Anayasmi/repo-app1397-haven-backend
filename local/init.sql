---
--- This script is used to initialize the database in LOCAL environment ONLY
--- Replace your_email_in_lowercase with your email in lowercase
---


insert into organization_groups (group_id, group_name, assistant_group_name, role_name, created_by, updated_by, created_at, updated_at, group_description, group_title)
values
('dc31e36c-ab19-4aae-9bf5-1f090873e5f0', 'ai-expert-assistant:legalai-expert-assistant:user', 'legalai-expert-assistant', 'user', your_email_in_lowercase, your_email_in_lowercase, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'Groups for LegalAI Expert Assistant', 'LegalAI Expert Assistant');

insert into organization_groups (group_id, group_name, assistant_group_name, role_name, created_by, updated_by, created_at, updated_at, group_description, group_title)
values
('df4b765c-9af4-4a5f-9563-5987e45a0118', 'ai-expert-assistant:legalai-expert-assistant:admin', 'legalai-expert-assistant', 'admin', your_email_in_lowercase, your_email_in_lowercase, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'Groups for LegalAI Expert Assistant', 'LegalAI Expert Assistant');

insert into assistants (assistant_name, description, endpoint, assistant_code) values 
('LegalAI Expert Assistant', 'Legal Assistant', 'http://localhost:8001', 'fc9a2924c51ca9e1e5b92901e635cffd37604252ec3dacf2a2b2b96e736578e6');

insert into assistant_permissions (assistant_id, group_id) values (1, 'dc31e36c-ab19-4aae-9bf5-1f090873e5f0');
insert into assistant_permissions (assistant_id, group_id) values (1, 'df4b765c-9af4-4a5f-9563-5987e45a0118');


insert into group_users (group_id, email, status, joined_at, created_at, updated_at)
values
('df4b765c-9af4-4a5f-9563-5987e45a0118', your_email_in_lowercase, 'CONFIRMED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);