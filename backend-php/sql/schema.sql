-- =========================================================================
-- AI-Assisted Cyber Threat Hunting & Attack Path Visualization Platform
-- Database Schema: MySQL 5.7+ / 8.0+ / MariaDB
-- =========================================================================

CREATE DATABASE IF NOT EXISTS `threat_hunter` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `threat_hunter`;

-- Drop existing tables if needed for clean re-installs
DROP TABLE IF EXISTS `investigation_reports`;
DROP TABLE IF EXISTS `incident_events`;
DROP TABLE IF EXISTS `incidents`;
DROP TABLE IF EXISTS `correlation_rules`;
DROP TABLE IF EXISTS `mitre_attack_matrix`;
DROP TABLE IF EXISTS `events`;
DROP TABLE IF EXISTS `attack_scenarios`;

-- 1. Attack Scenarios Catalog
CREATE TABLE `attack_scenarios` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scenario_id` VARCHAR(64) NOT NULL UNIQUE,
    `name` VARCHAR(255) NOT NULL,
    `threat_actor` VARCHAR(100) NOT NULL,
    `description` TEXT NOT NULL,
    `target_environment` VARCHAR(255) NOT NULL,
    `attack_vector` VARCHAR(255) NOT NULL,
    `impact` TEXT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Normalized Security Telemetry Events Table
-- Ingests Endpoint (EDR/Sysmon), Identity/Auth, Network (Zeek/Suricata), and Cloud (CloudTrail/Azure)
CREATE TABLE `events` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `event_uuid` VARCHAR(64) NOT NULL UNIQUE,
    `scenario_id` VARCHAR(64) NOT NULL,
    `timestamp` DATETIME NOT NULL,
    `domain` ENUM('endpoint', 'auth', 'network', 'cloud') NOT NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `severity` ENUM('informational', 'low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    `source_host` VARCHAR(100) NULL,
    `dest_host` VARCHAR(100) NULL,
    `source_ip` VARCHAR(45) NULL,
    `dest_ip` VARCHAR(45) NULL,
    `user_id` VARCHAR(100) NULL,
    `process_name` VARCHAR(255) NULL,
    `command_line` TEXT NULL,
    `parent_process` VARCHAR(255) NULL,
    `cloud_service` VARCHAR(100) NULL,
    `cloud_action` VARCHAR(100) NULL,
    `mitre_tactic` VARCHAR(100) NULL,
    `mitre_technique_id` VARCHAR(50) NULL,
    `mitre_technique_name` VARCHAR(255) NULL,
    `raw_payload` JSON NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_scenario_time` (`scenario_id`, `timestamp`),
    INDEX `idx_domain` (`domain`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_user` (`user_id`),
    INDEX `idx_source_host` (`source_host`),
    INDEX `idx_dest_ip` (`dest_ip`),
    INDEX `idx_mitre_technique` (`mitre_technique_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. MITRE ATT&CK Framework Reference Table
CREATE TABLE `mitre_attack_matrix` (
    `technique_id` VARCHAR(50) PRIMARY KEY,
    `technique_name` VARCHAR(255) NOT NULL,
    `tactic` VARCHAR(100) NOT NULL,
    `tactic_order` INT NOT NULL DEFAULT 1,
    `description` TEXT NOT NULL,
    `detection_guidance` TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Behavioral & Cross-Domain Correlation Rules
CREATE TABLE `correlation_rules` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `rule_id` VARCHAR(50) NOT NULL UNIQUE,
    `rule_name` VARCHAR(255) NOT NULL,
    `description` TEXT NOT NULL,
    `tactic` VARCHAR(100) NOT NULL,
    `sliding_window_minutes` INT NOT NULL DEFAULT 60,
    `severity` VARCHAR(20) NOT NULL DEFAULT 'high',
    `is_active` TINYINT(1) DEFAULT 1,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Reconstructed Incidents & Attack Paths
CREATE TABLE `incidents` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `incident_id` VARCHAR(64) NOT NULL UNIQUE,
    `scenario_id` VARCHAR(64) NOT NULL,
    `title` VARCHAR(255) NOT NULL,
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'high',
    `confidence_score` DECIMAL(4,2) NOT NULL DEFAULT 0.85,
    `status` ENUM('new', 'investigating', 'contained', 'resolved') NOT NULL DEFAULT 'investigating',
    `affected_hosts` JSON NULL,
    `affected_users` JSON NULL,
    `ai_summary` TEXT NULL,
    `investigation_lead` TEXT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scenario_id`) REFERENCES `attack_scenarios`(`scenario_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. Incident to Event Junction (Chain of Custody Evidence)
CREATE TABLE `incident_events` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `incident_id` VARCHAR(64) NOT NULL,
    `event_uuid` VARCHAR(64) NOT NULL,
    `sequence_order` INT NOT NULL,
    `correlation_reason` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`incident_id`) REFERENCES `incidents`(`incident_id`) ON DELETE CASCADE,
    FOREIGN KEY (`event_uuid`) REFERENCES `events`(`event_uuid`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. Formal Investigation Reports Table
CREATE TABLE `investigation_reports` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `report_id` VARCHAR(64) NOT NULL UNIQUE,
    `incident_id` VARCHAR(64) NOT NULL,
    `analyst_name` VARCHAR(100) NOT NULL,
    `executive_summary` TEXT NOT NULL,
    `attack_path_summary` TEXT NOT NULL,
    `containment_recommendations` JSON NOT NULL,
    `mitre_coverage` JSON NOT NULL,
    `evidence_chain` JSON NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`incident_id`) REFERENCES `incidents`(`incident_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
