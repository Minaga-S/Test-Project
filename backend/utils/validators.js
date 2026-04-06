/**
 * Input Validators
 */
// NOTE: Utility helpers: shared reusable functions/constants used across modules.

const LIVE_SCAN_FREQUENCIES = ['OnDemand', 'Daily', 'Weekly'];
const HOSTNAME_PATTERN = /^[a-zA-Z0-9.-]+$/;
const IPV4_PATTERN = /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/;
const PORT_LIST_PATTERN = /^$|^\d{1,5}(,\d{1,5})*$/;
const PROFILE_TEXT_PATTERN = /^[a-zA-Z0-9 .,_\-/]{0,80}$/;
const PROFILE_VERSION_PATTERN = /^[a-zA-Z0-9 ._\-]{0,40}$/;
const CPE_URI_PATTERN = /^$|^cpe:2\.3:[aho]:[a-z0-9._-]+:[a-z0-9._-]+:[a-z0-9*._-]*(:[a-z0-9*._-]*){0,7}$/i;

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password && password.length >= 8;
}

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

function isLiveScanEnabled(value) {
    return value === true || value === 'true';
}

function isValidScanTarget(value) {
    if (!isNonEmptyString(value)) {
        return false;
    }

    const normalizedValue = value.trim();
    return IPV4_PATTERN.test(normalizedValue) || HOSTNAME_PATTERN.test(normalizedValue);
}

function validateVulnerabilityProfile(profile = {}) {
    const errors = {};

    if (isNonEmptyString(profile.osName) && !PROFILE_TEXT_PATTERN.test(profile.osName.trim())) {
        errors.osName = 'OS name contains invalid characters';
    }

    if (isNonEmptyString(profile.vendor) && !PROFILE_TEXT_PATTERN.test(profile.vendor.trim())) {
        errors.vendor = 'Vendor contains invalid characters';
    }

    if (isNonEmptyString(profile.product) && !PROFILE_TEXT_PATTERN.test(profile.product.trim())) {
        errors.product = 'Product contains invalid characters';
    }

    if (isNonEmptyString(profile.productVersion) && !PROFILE_VERSION_PATTERN.test(profile.productVersion.trim())) {
        errors.productVersion = 'Product version contains invalid characters';
    }

    if (isNonEmptyString(profile.cpeUri) && !CPE_URI_PATTERN.test(profile.cpeUri.trim())) {
        errors.cpeUri = 'CPE URI must use cpe:2.3 format';
    }

    return errors;
}

function validateAsset(assetData) {
    const errors = {};

    if (!assetData.assetName || !assetData.assetName.trim()) {
        errors.assetName = 'Asset name is required';
    }

    if (!assetData.assetType) {
        errors.assetType = 'Asset type is required';
    }

    if (!assetData.criticality) {
        errors.criticality = 'Criticality level is required';
    }

    const liveScan = assetData.liveScan || {};

    if (isLiveScanEnabled(liveScan.enabled) && !isNonEmptyString(liveScan.target)) {
        errors.scanTarget = 'Scan target is required when live scan is enabled';
    }

    if (isNonEmptyString(liveScan.target) && !isValidScanTarget(liveScan.target)) {
        errors.scanTarget = 'Scan target must be a valid IPv4 address or hostname';
    }

    if (isNonEmptyString(liveScan.ports) && !PORT_LIST_PATTERN.test(liveScan.ports.trim())) {
        errors.scanPorts = 'Scan ports must be a comma-separated list of port numbers';
    }

    if (liveScan.frequency && !LIVE_SCAN_FREQUENCIES.includes(liveScan.frequency)) {
        errors.scanFrequency = 'Scan frequency is invalid';
    }

    const vulnerabilityErrors = validateVulnerabilityProfile(assetData.vulnerabilityProfile || {});
    Object.assign(errors, vulnerabilityErrors);

    return {
        isValid: Object.keys(errors).length === 0,
        errors,
    };
}

function validateIncident(incidentData) {
    const errors = {};

    if (!incidentData.assetId) {
        errors.assetId = 'Asset ID is required';
    }

    if (!incidentData.description || incidentData.description.trim().length < 20) {
        errors.description = 'Description must be at least 20 characters';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors,
    };
}

module.exports = {
    validateEmail,
    validatePassword,
    validateAsset,
    validateIncident,
    validateVulnerabilityProfile,
};