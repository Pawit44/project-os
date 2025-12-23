/**
 * Dashboard Charts and Data Loading
 * Uses Chart.js for visualizations
 */

// Chart instances
let timelineChart = null;
let threatChart = null;
let countriesChart = null;
let sourcesChart = null;

// Chart colors
const colors = {
    blue: 'rgba(77, 168, 218, 0.8)',
    green: 'rgba(46, 204, 113, 0.8)',
    orange: 'rgba(243, 156, 18, 0.8)',
    red: 'rgba(231, 76, 60, 0.8)',
    purple: 'rgba(155, 89, 182, 0.8)',
    gray: 'rgba(160, 160, 160, 0.8)',
};

const bgColors = {
    blue: 'rgba(77, 168, 218, 0.2)',
    green: 'rgba(46, 204, 113, 0.2)',
    orange: 'rgba(243, 156, 18, 0.2)',
    red: 'rgba(231, 76, 60, 0.2)',
    purple: 'rgba(155, 89, 182, 0.2)',
};

// Chart.js global config
Chart.defaults.color = '#a0a0a0';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';

/**
 * Load all dashboard data
 */
async function loadDashboardData() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        updateStatCards(data);
        updateCharts(data);
        updateLists(data);
        await loadRecentAttacks();
        await loadBlockedIPs();

        updateLastUpdate();
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

/**
 * Update stat cards
 */
function updateStatCards(data) {
    document.getElementById('total-attacks').textContent = data.total_attacks.toLocaleString();
    document.getElementById('unique-ips').textContent = data.unique_ips.toLocaleString();
    document.getElementById('blocked-ips').textContent = data.blocked_ips.toLocaleString();
    document.getElementById('high-threats').textContent = data.high_threats.toLocaleString();
    document.getElementById('today-attacks').textContent = data.today_attacks.toLocaleString();
}

/**
 * Update all charts
 */
function updateCharts(data) {
    updateTimelineChart(data.hourly_stats);
    updateThreatChart(data.threat_distribution);
    updateCountriesChart(data.top_countries);
    updateSourcesChart(data.attacks_by_source);
}

/**
 * Timeline Chart - Attacks per hour
 */
function updateTimelineChart(hourlyStats) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    const labels = hourlyStats.map(h => {
        const date = new Date(h.hour);
        return date.getHours() + ':00';
    });
    const values = hourlyStats.map(h => h.count);

    if (timelineChart) {
        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = values;
        timelineChart.update();
    } else {
        timelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: values,
                    borderColor: colors.blue,
                    backgroundColor: bgColors.blue,
                    tension: 0.4,
                    fill: true,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    },
                    x: {
                        grid: { display: false }
                    }
                }
            }
        });
    }
}

/**
 * Threat Level Distribution Chart
 */
function updateThreatChart(distribution) {
    const ctx = document.getElementById('threatChart');
    if (!ctx) return;

    const labels = Object.keys(distribution);
    const values = Object.values(distribution);
    const chartColors = labels.map(l => {
        if (l === 'HIGH') return colors.red;
        if (l === 'MEDIUM') return colors.orange;
        return colors.green;
    });

    if (threatChart) {
        threatChart.data.labels = labels;
        threatChart.data.datasets[0].data = values;
        threatChart.update();
    } else {
        threatChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: chartColors,
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                    }
                }
            }
        });
    }
}

/**
 * Top Countries Chart
 */
function updateCountriesChart(topCountries) {
    const ctx = document.getElementById('countriesChart');
    if (!ctx) return;

    const labels = topCountries.map(c => c.country || 'Unknown');
    const values = topCountries.map(c => c.count);

    if (countriesChart) {
        countriesChart.data.labels = labels;
        countriesChart.data.datasets[0].data = values;
        countriesChart.update();
    } else {
        countriesChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: values,
                    backgroundColor: colors.purple,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    },
                    y: {
                        grid: { display: false }
                    }
                }
            }
        });
    }
}

/**
 * Attack Sources Chart
 */
function updateSourcesChart(sources) {
    const ctx = document.getElementById('sourcesChart');
    if (!ctx) return;

    const labels = Object.keys(sources);
    const values = Object.values(sources);
    const chartColors = labels.map(l => {
        if (l === 'WEB') return colors.blue;
        if (l === 'SSH') return colors.purple;
        return colors.gray;
    });

    if (sourcesChart) {
        sourcesChart.data.labels = labels;
        sourcesChart.data.datasets[0].data = values;
        sourcesChart.update();
    } else {
        sourcesChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: chartColors,
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                    }
                }
            }
        });
    }
}

/**
 * Update top lists
 */
function updateLists(data) {
    // Top passwords
    const passwordsList = document.getElementById('top-passwords');
    if (passwordsList) {
        passwordsList.innerHTML = data.top_passwords.slice(0, 10).map(p =>
            `<li><span class="item-name">${escapeHtml(p.password)}</span>
             <span class="item-count">${p.count}</span></li>`
        ).join('') || '<li>No data</li>';
    }

    // Top usernames
    const usernamesList = document.getElementById('top-usernames');
    if (usernamesList) {
        usernamesList.innerHTML = data.top_usernames.slice(0, 10).map(u =>
            `<li><span class="item-name">${escapeHtml(u.username)}</span>
             <span class="item-count">${u.count}</span></li>`
        ).join('') || '<li>No data</li>';
    }
}

/**
 * Load recent attacks
 */
async function loadRecentAttacks() {
    try {
        const response = await fetch('/api/attacks?limit=10');
        const data = await response.json();

        const tbody = document.getElementById('recent-attacks-body');
        if (!tbody) return;

        if (data.attacks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6">No attacks recorded</td></tr>';
            return;
        }

        tbody.innerHTML = data.attacks.map(attack => {
            const time = new Date(attack.timestamp).toLocaleString();
            const levelClass = attack.threat_level.toLowerCase();

            return `
                <tr class="threat-${levelClass}">
                    <td>${time}</td>
                    <td><span class="source-badge ${attack.source.toLowerCase()}">${attack.source}</span></td>
                    <td class="ip-cell">${attack.ip_address}</td>
                    <td>${attack.country || 'Unknown'}</td>
                    <td>${attack.username || '-'}</td>
                    <td><span class="threat-badge ${levelClass}">${attack.threat_level}</span></td>
                </tr>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading recent attacks:', error);
    }
}

/**
 * Load blocked IPs
 */
async function loadBlockedIPs() {
    try {
        const response = await fetch('/api/blocked');
        const data = await response.json();

        const list = document.getElementById('blocked-list');
        if (!list) return;

        if (data.blocked_ips.length === 0) {
            list.innerHTML = '<li>No blocked IPs</li>';
            return;
        }

        list.innerHTML = data.blocked_ips.slice(0, 10).map(ip => {
            const expiresAt = new Date(ip.expires_at).toLocaleTimeString();
            return `
                <li>
                    <span class="item-name">${ip.ip_address}</span>
                    <span class="item-count">until ${expiresAt}</span>
                </li>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading blocked IPs:', error);
    }
}

/**
 * Update last update time
 */
function updateLastUpdate() {
    const element = document.getElementById('last-update');
    if (element) {
        element.textContent = 'Updated: ' + new Date().toLocaleTimeString();
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initial load when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    loadDashboardData();
});
