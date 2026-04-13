/**
 * Escapes HTML entities to prevent XSS.
 * @param {string} str - Raw string from server data.
 * @returns {string} Sanitized string safe for innerHTML.
 */
export function sanitize(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
