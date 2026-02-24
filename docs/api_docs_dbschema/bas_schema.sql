--
-- PostgreSQL database dump
--

\restrict tUdLpIAaHL1t7R5zyoMON3UJwLvXoVmOLIkZhlXwtmWLJQrKicsg6KXAqdXRAPI

-- Dumped from database version 16.11
-- Dumped by pg_dump version 16.11

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: postgres
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO postgres;

--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON SCHEMA public IS '';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: abilities; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.abilities (
    ability_id uuid NOT NULL,
    name character varying(150) NOT NULL,
    description character varying,
    mitre_tactic character varying(100),
    mitre_technique_id character varying(50),
    platform character varying(50),
    impact_type character varying(50),
    default_severity character varying(20),
    requires_approval boolean,
    tags jsonb,
    created_by character varying(50) DEFAULT 'manual'::character varying NOT NULL
);


ALTER TABLE public.abilities OWNER TO postgres;

--
-- Name: ability_stages; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ability_stages (
    stage_id uuid NOT NULL,
    ability_id uuid NOT NULL,
    stage_name character varying(150),
    stage_order integer NOT NULL,
    executor character varying(100),
    command_template text,
    payload_id uuid,
    expected_outcome text,
    success_criteria text,
    failure_criteria text,
    timeout_seconds integer,
    rollback_command text
);


ALTER TABLE public.ability_stages OWNER TO postgres;

--
-- Name: adversaries; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.adversaries (
    adversary_id uuid NOT NULL,
    name character varying(150) NOT NULL,
    description text,
    profile text,
    execution_strategy text
);


ALTER TABLE public.adversaries OWNER TO postgres;

--
-- Name: adversary_abilities; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.adversary_abilities (
    adversary_id uuid NOT NULL,
    ability_id uuid NOT NULL
);


ALTER TABLE public.adversary_abilities OWNER TO postgres;

--
-- Name: agents; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.agents (
    agent_id character varying(8) NOT NULL,
    hostname character varying(150) NOT NULL,
    ip_address character varying(45),
    platform character varying(50) DEFAULT 'windows'::character varying,
    last_seen timestamp without time zone,
    registered_at timestamp without time zone DEFAULT now(),
    is_enabled boolean DEFAULT true
);


ALTER TABLE public.agents OWNER TO postgres;

--
-- Name: approvals; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.approvals (
    approval_id uuid NOT NULL,
    entity_type character varying(50),
    entity_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    approved_by uuid,
    status character varying(50),
    reason text,
    "timestamp" timestamp without time zone
);


ALTER TABLE public.approvals OWNER TO postgres;

--
-- Name: detections; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.detections (
    detection_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    control_name character varying(150),
    detected boolean,
    detection_time timestamp without time zone,
    evidence text
);


ALTER TABLE public.detections OWNER TO postgres;

--
-- Name: environments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.environments (
    environment_id uuid NOT NULL,
    name character varying(150) NOT NULL,
    environment_type character varying(20),
    risk_tolerance character varying(20),
    network_ranges jsonb,
    allowed_tactics jsonb,
    blocked_techniques jsonb,
    monitoring_stack jsonb,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.environments OWNER TO postgres;

--
-- Name: execution_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.execution_logs (
    execution_log_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    ability_id uuid,
    stage_id uuid,
    "timestamp" timestamp without time zone,
    executor character varying(100),
    command_executed text,
    stdout text,
    stderr text,
    exit_code integer
);


ALTER TABLE public.execution_logs OWNER TO postgres;

--
-- Name: findings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.findings (
    finding_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    ability_id uuid,
    environment_id uuid NOT NULL,
    finding_type character varying(50),
    severity character varying(20),
    confidence double precision,
    status character varying(50)
);


ALTER TABLE public.findings OWNER TO postgres;

--
-- Name: operations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.operations (
    operation_id uuid NOT NULL,
    name character varying(150) NOT NULL,
    adversary_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    initiated_by_user_id uuid,
    execution_mode character varying(50),
    status character varying(50),
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    kill_switch_triggered boolean
);


ALTER TABLE public.operations OWNER TO postgres;

--
-- Name: payloads; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.payloads (
    payload_id uuid NOT NULL,
    name character varying(150) NOT NULL,
    platform character varying(50),
    type character varying(50),
    payload_hash character varying(256),
    risk_classification character varying(50),
    approved boolean,
    sandbox_verified boolean,
    filename character varying(255),
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.payloads OWNER TO postgres;

--
-- Name: roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.roles (
    role_id uuid NOT NULL,
    name character varying(100) NOT NULL,
    permissions jsonb NOT NULL
);


ALTER TABLE public.roles OWNER TO postgres;

--
-- Name: user_credentials; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_credentials (
    credential_id uuid NOT NULL,
    user_id uuid,
    auth_type character varying(20) NOT NULL,
    password_hash character varying,
    password_algo character varying(50),
    mfa_enabled boolean,
    last_password_change timestamp without time zone
);


ALTER TABLE public.user_credentials OWNER TO postgres;

--
-- Name: user_sessions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_sessions (
    session_id uuid NOT NULL,
    user_id uuid NOT NULL,
    ip_address character varying(45),
    user_agent character varying,
    created_at timestamp without time zone,
    expires_at timestamp without time zone,
    revoked boolean
);


ALTER TABLE public.user_sessions OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id uuid NOT NULL,
    name character varying(150) NOT NULL,
    email character varying(255) NOT NULL,
    role_id uuid,
    status character varying(50),
    created_at timestamp without time zone
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: abilities abilities_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.abilities
    ADD CONSTRAINT abilities_pkey PRIMARY KEY (ability_id);


--
-- Name: ability_stages ability_stages_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ability_stages
    ADD CONSTRAINT ability_stages_pkey PRIMARY KEY (stage_id);


--
-- Name: adversaries adversaries_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.adversaries
    ADD CONSTRAINT adversaries_pkey PRIMARY KEY (adversary_id);


--
-- Name: adversary_abilities adversary_abilities_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.adversary_abilities
    ADD CONSTRAINT adversary_abilities_pkey PRIMARY KEY (adversary_id, ability_id);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (agent_id);


--
-- Name: approvals approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_pkey PRIMARY KEY (approval_id);


--
-- Name: detections detections_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_pkey PRIMARY KEY (detection_id);


--
-- Name: environments environments_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_pkey PRIMARY KEY (environment_id);


--
-- Name: execution_logs execution_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.execution_logs
    ADD CONSTRAINT execution_logs_pkey PRIMARY KEY (execution_log_id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (finding_id);


--
-- Name: operations operations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (operation_id);


--
-- Name: payloads payloads_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.payloads
    ADD CONSTRAINT payloads_pkey PRIMARY KEY (payload_id);


--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);


--
-- Name: user_credentials user_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_credentials
    ADD CONSTRAINT user_credentials_pkey PRIMARY KEY (credential_id);


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (session_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: ability_stages ability_stages_ability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ability_stages
    ADD CONSTRAINT ability_stages_ability_id_fkey FOREIGN KEY (ability_id) REFERENCES public.abilities(ability_id) ON DELETE CASCADE;


--
-- Name: adversary_abilities adversary_abilities_ability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.adversary_abilities
    ADD CONSTRAINT adversary_abilities_ability_id_fkey FOREIGN KEY (ability_id) REFERENCES public.abilities(ability_id) ON DELETE CASCADE;


--
-- Name: adversary_abilities adversary_abilities_adversary_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.adversary_abilities
    ADD CONSTRAINT adversary_abilities_adversary_id_fkey FOREIGN KEY (adversary_id) REFERENCES public.adversaries(adversary_id) ON DELETE CASCADE;


--
-- Name: approvals approvals_approved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES public.users(user_id);


--
-- Name: approvals approvals_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public.users(user_id);


--
-- Name: detections detections_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(finding_id) ON DELETE CASCADE;


--
-- Name: execution_logs execution_logs_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.execution_logs
    ADD CONSTRAINT execution_logs_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES public.operations(operation_id) ON DELETE CASCADE;


--
-- Name: findings findings_ability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_ability_id_fkey FOREIGN KEY (ability_id) REFERENCES public.abilities(ability_id);


--
-- Name: findings findings_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(environment_id);


--
-- Name: findings findings_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES public.operations(operation_id) ON DELETE CASCADE;


--
-- Name: ability_stages fk_payload_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ability_stages
    ADD CONSTRAINT fk_payload_id FOREIGN KEY (payload_id) REFERENCES public.payloads(payload_id) ON DELETE SET NULL;


--
-- Name: operations operations_adversary_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.operations
    ADD CONSTRAINT operations_adversary_id_fkey FOREIGN KEY (adversary_id) REFERENCES public.adversaries(adversary_id);


--
-- Name: operations operations_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.operations
    ADD CONSTRAINT operations_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(environment_id);


--
-- Name: operations operations_initiated_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.operations
    ADD CONSTRAINT operations_initiated_by_user_id_fkey FOREIGN KEY (initiated_by_user_id) REFERENCES public.users(user_id);


--
-- Name: user_credentials user_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_credentials
    ADD CONSTRAINT user_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_sessions user_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: users users_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;


--
-- PostgreSQL database dump complete
--

\unrestrict tUdLpIAaHL1t7R5zyoMON3UJwLvXoVmOLIkZhlXwtmWLJQrKicsg6KXAqdXRAPI

