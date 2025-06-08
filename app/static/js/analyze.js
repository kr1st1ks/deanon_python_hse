let quickData = null
let dnsLeakResult = null
let userIp = null

// =====================
// Получение публичного IP через ipify
// =====================
async function getUserIp() {
    try {
        const resp = await fetch('https://api.ipify.org?format=json')
        const data = await resp.json()
        return data.ip
    } catch (e) {
        console.error("Не удалось определить IP:", e)
        return null
    }
}

// =====================
// Основной анализ по IP (получение и отображение сведений)
// =====================
async function fetchQuickData() {
    userIp = await getUserIp()
    if (!userIp) {
        document.getElementById('ip-address').innerText = 'Ошибка'
        return
    }
    const resp = await fetch(`/analyze/quick?client_ip=${encodeURIComponent(userIp)}`)
    if (!resp.ok) {
        document.getElementById('ip-address').innerText = 'Ошибка'
        document.querySelectorAll('.info-list .value').forEach(el => {
            el.innerText = 'Ошибка'
        })
        return
    }
    const data = await resp.json()
    quickData = data

    // --- Отображение IP-адреса ---
    if (data.ip_location && data.ip_location.ip) {
        document.getElementById('ip-address').innerText = data.ip_location.ip
    } else if (data.whois_info && data.whois_info.ip) {
        document.getElementById('ip-address').innerText = data.whois_info.ip
    } else {
        document.getElementById('ip-address').innerText = 'Не определено'
    }

    // --- Хостнейм ---
    let hostVal = 'Не определено'
    if (data.full_resolve && data.full_resolve.subdomains && data.full_resolve.subdomains.length > 0) {
        hostVal = data.full_resolve.subdomains[0]
    }
    document.getElementById('hostname-value').innerText = hostVal

    // --- Операционная система ---
    let osVal = 'Не определено'
    if (data.os_info && data.os_info.os) {
        osVal = data.os_info.os
    }
    document.getElementById('os-value').innerText = osVal

    // --- Геолокация (город, страна) ---
    let locStr = 'Не определено'
    if (data.ip_location) {
        const city = data.ip_location.city || ''
        const countryCode = data.ip_location.country || ''
        let countryName = countryCode
        // Форматирование кода страны в название страны, если поддерживается браузером
        if (countryCode) {
            try {
                if (Intl && Intl.DisplayNames) {
                    const regionNames = new Intl.DisplayNames(['en'], {type: 'region'})
                    countryName = regionNames.of(countryCode)
                }
            } catch (e) {
                countryName = countryCode
            }
        }
        if (city && countryName) {
            locStr = city + ', ' + countryName
        } else if (countryName) {
            locStr = countryName
        } else if (city) {
            locStr = city
        }
    }
    document.getElementById('location-value').innerText = locStr

    // --- Провайдер (ISP) ---
    let providerStr = 'Не определено'
    if (data.ip_location && data.ip_location.provider) {
        providerStr = data.ip_location.provider
    } else if (data.whois_info && data.whois_info.nets && data.whois_info.nets.length > 0) {
        const netInfo = data.whois_info.nets[0]
        providerStr = netInfo.name || netInfo.description || providerStr
    }
    providerStr = providerStr.replace(/^AS\d+\s+/, '')
    if (!providerStr) providerStr = 'Не определено'
    document.getElementById('provider-value').innerText = providerStr

    // --- Использование VPN ---
    let vpnText = 'Не используется'
    if (data.anonymization_info && data.anonymization_info.vpn_detected) {
        vpnText = 'Используется'
        if (data.anonymization_info.vpn_provider) {
            vpnText += ' (' + data.anonymization_info.vpn_provider + ')'
        }
    }
    document.getElementById('vpn-value').innerText = vpnText

    // --- Использование Tor ---
    let torText = 'Не используется'
    if (data.anonymization_info && data.anonymization_info.tor_detected) {
        torText = 'Используется'
        if (data.anonymization_info.tor_exit_location) {
            torText += ' (выход: ' + data.anonymization_info.tor_exit_location + ')'
        }
    }
    document.getElementById('tor-value').innerText = torText

    // --- Открытые порты ---
    let portsText = 'Отсутствуют'
    if (data.port_scan_info && data.port_scan_info.open_ports) {
        let openPorts = data.port_scan_info.open_ports
        // Приведение set к массиву, если нужно
        if (!Array.isArray(openPorts)) {
            openPorts = Array.from(openPorts)
        }
        if (openPorts.length > 0) {
            openPorts.sort((a, b) => parseInt(a) - parseInt(b))
            const portList = openPorts.map(item => {
                const parts = item.split(':')
                return parts.length > 1 ? `${parts[0]} (${parts[1] || ''})` : parts[0]
            })
            portsText = portList.join(', ')
        }
    }
    document.getElementById('ports-value').innerText = portsText

    // --- Проверка по DNSBL-черным спискам ---
    let secText = 'Не обнаружено'
    if (data.security_info) {
        if (Array.isArray(data.security_info.blacklisted) && data.security_info.blacklisted.length > 0) {
            const listNames = data.security_info.blacklisted.map(entry => entry.dnsbl).filter(n => n).join(', ')
            secText = 'Обнаружено'
            if (listNames) {
                secText += ': ' + listNames
            }
            document.getElementById('blacklist-value').classList.add('alert')
        } else if (data.security_info.blacklisted === false) {
            secText = 'Не обнаружено'
        } else if (data.security_info.blacklisted) {
            secText = 'Обнаружено'
            document.getElementById('blacklist-value').classList.add('alert')
        }
    }
    document.getElementById('blacklist-value').innerText = secText

    // --- Иконки ОС и браузера ---
    updateIcons(osVal, browserVal)
}

// =====================
// DNS Leak test: POST /dnsleak/start, затем GET /dnsleak/check?test_id=...
// =====================
async function startDnsLeakTest() {
    const resp = await fetch('/dnsleak/start', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
    })
    if (!resp.ok) {
        document.getElementById('dnsleak-value').innerText = 'Ошибка'
        return
    }
    const data = await resp.json()
    if (!data.test_id || !data.domains) {
        document.getElementById('dnsleak-value').innerText = 'Ошибка'
        return
    }
    const testId = data.test_id

    // Проверка результата через небольшую задержку, чтобы DNS-запрос успел пройти
    setTimeout(async () => {
        try {
            const res = await fetch(`/dnsleak/check?test_id=${testId}`)
            if (!res.ok) {
                document.getElementById('dnsleak-value').innerText = 'Ошибка'
                return
            }
            const result = await res.json()
            result.leak_detected = false
            dnsLeakResult = result
            let leakText = 'Не обнаружена'
            document.getElementById('dnsleak-value').innerText = leakText
            if (result.leak_detected === true) {
                leakText = 'Обнаружена!'
                document.getElementById('dnsleak-value').classList.add('alert')
            } else {
                document.getElementById('dnsleak-value').classList.remove('alert')
            }
        } catch (e) {
            document.getElementById('dnsleak-value').innerText = 'Ошибка'
        }
    }, 300)
}

// =====================
// Копирование IP и результатов, скачивание результатов как JSON
// =====================

// Копирование IP-адреса (с анимацией иконки)
document.getElementById('copy-ip-btn').addEventListener('click', () => {
    const ipText = document.getElementById('ip-address').innerText
    if (!ipText || ipText === 'Ошибка' || ipText === '...') return
    navigator.clipboard.writeText(ipText).then(() => {
        const icon = document.getElementById('copy-ip-btn').querySelector('i')
        icon.classList.remove('fa-copy')
        icon.classList.add('fa-check')
        icon.style.color = '#4caf50'
        setTimeout(() => {
            icon.classList.remove('fa-check')
            icon.classList.add('fa-copy')
            icon.style.color = ''
        }, 2000)
    }).catch(err => {
        console.error('Copy IP failed:', err)
    })
})

// Копирование всех сведений в буфер обмена
document.getElementById('copy-result-btn').addEventListener('click', (e) => {
    e.preventDefault()
    let text = 'Ваш IP-адрес: ' + (document.getElementById('ip-address').innerText || '') + '\n'
    document.querySelectorAll('.info-list li').forEach(li => {
        text += li.innerText + '\n'
    })
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copy-result-btn')
        const originalText = btn.innerText
        btn.innerText = 'Скопировано!'
        setTimeout(() => {
            btn.innerText = originalText
        }, 2000)
    }).catch(err => {
        console.error('Copy result failed:', err)
    })
})

// Скачивание результатов анализа как JSON
document.getElementById('download-json-btn').addEventListener('click', (e) => {
    e.preventDefault()
    if (!quickData && !dnsLeakResult) {
        console.warn('No data to download')
        return
    }
    const combined = {
        analysis: quickData, dns_leak: dnsLeakResult
    }
    const blob = new Blob([JSON.stringify(combined, null, 2)], {type: 'application/json'})
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'analysis_result.json'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
})

// =====================
// Инициализация страницы (запуск анализа и теста DNS при загрузке)
// =====================
window.addEventListener('DOMContentLoaded', async () => {
    await startDnsLeakTest()
    await fetchQuickData()
})

// =====================
// Функция обновления иконок ОС и браузера (работает по названию)
// =====================
function updateIcons(osName, browserName) {
    const osIcon = document.getElementById('os-icon')
    const browserIcon = document.getElementById('browser-icon')
    if (osIcon && osName) {
        const osLower = osName.toLowerCase()
        let iconClass = 'fa-desktop', prefixClass = 'fas'
        if (osLower.includes('windows')) {
            iconClass = 'fa-windows'
            prefixClass = 'fab'
        } else if (osLower.includes('mac') || osLower.includes('ios')) {
            iconClass = 'fa-apple'
            prefixClass = 'fab'
        } else if (osLower.includes('android')) {
            iconClass = 'fa-android'
            prefixClass = 'fab'
        } else if (osLower.includes('ubuntu') || osLower.includes('debian') || osLower.includes('fedora') || osLower.includes('arch') || osLower.includes('linux')) {
            iconClass = 'fa-linux'
            prefixClass = 'fab'
        }
        osIcon.className = `${prefixClass} ${iconClass}`
    }
    if (browserIcon && browserName) {
        const brLower = browserName.toLowerCase()
        let iconClass = 'fa-globe', prefixClass = 'fas'
        if (brLower.includes('firefox')) {
            iconClass = 'fa-firefox'
            prefixClass = 'fab'
        } else if (brLower.includes('edge')) {
            iconClass = 'fa-edge'
            prefixClass = 'fab'
        } else if (brLower.includes('chrome')) {
            if (!brLower.includes('chromium')) {
                iconClass = 'fa-chrome'
                prefixClass = 'fab'
            } else {
                iconClass = 'fa-chrome'
                prefixClass = 'fab'
            }
        } else if (brLower.includes('safari')) {
            iconClass = 'fa-safari'
            prefixClass = 'fab'
        } else if (brLower.includes('opera') || brLower.includes('opr')) {
            iconClass = 'fa-opera'
            prefixClass = 'fab'
        } else if (brLower.includes('internet explorer') || brLower.includes('trident') || brLower.includes('msie')) {
            iconClass = 'fa-internet-explorer'
            prefixClass = 'fab'
        }
        browserIcon.className = `${prefixClass} ${iconClass}`
    }
}