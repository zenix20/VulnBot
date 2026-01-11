document.addEventListener('DOMContentLoaded', function () {
    // DOM Elements
    const chatContainer = document.getElementById('chatContainer');
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');
    const messagesEnd = document.getElementById('messagesEnd');

    // State
    let currentCVE = null;

    // Event Listeners
    messageForm.addEventListener('submit', handleSubmit);
    messageInput.addEventListener('input', handleInputChange);

    // Use event delegation for dynamically created buttons
    // Button event delegation
    chatContainer.addEventListener('click', function (e) {
        // Handle copy button clicks
        if (e.target.classList.contains('copy-button') || e.target.closest('.copy-button')) {
            const button = e.target.classList.contains('copy-button')
                ? e.target
                : e.target.closest('.copy-button');
            copyToClipboard(button);
        }

        // Handle download button clicks
        if (e.target.classList.contains('download-button') || e.target.closest('.download-button')) {
            downloadPDF();
        }
    });

    chatContainer.addEventListener('click', function (e) {
        // Handle simple explanation toggle
        const simpleHeader = e.target.closest('.simple-header');
        if (simpleHeader) {
            const simpleSection = simpleHeader.closest('.bg-gradient-to-r');
            simpleSection.classList.toggle('collapsed');
        }
    });

    // Functions
    async function handleSubmit(e) {
        e.preventDefault();
        const inputText = messageInput.value.trim();
        if (!inputText) return;

        // Add user message
        addMessage({
            type: 'user',
            content: inputText
        });

        // Check if input is a CVE ID
        const cvePattern = /^CVE-\d{4}-\d{4,}$/i;
        if (cvePattern.test(inputText)) {
            // Show loading message
            const loadingElement = addMessage({
                type: 'bot',
                content: `Fetching details for ${inputText.toUpperCase()}...`,
                loading: true
            });

            try {
                const response = await fetch('http://127.0.0.1:8000/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ cve_id: inputText })
                });

                // Remove loading message
                chatContainer.removeChild(loadingElement);

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'API request failed');
                }

                const data = await response.json();

                // Format the response for your UI
                const formattedData = {
                    id: data.metadata.id,
                    cvssScore: data.metadata.cvssScore,
                    severity: data.metadata.severity.toLowerCase(),
                    attackVector: data.metadata.attackVector,
                    exploitability: data.metadata.cvssScore >= 7.0 ? "High" : "Medium",
                    affectedProducts: data.metadata.affectedProducts,
                    description: data.metadata.description,
                    privilegesRequired: data.metadata.privilegesRequired,
                    userInteraction: data.metadata.userInteraction,
                    confidentialityImpact: data.metadata.confidentialityImpact,
                    integrityImpact: data.metadata.integrityImpact,
                    availabilityImpact: data.metadata.availabilityImpact,
                    sourceIdentifier: data.metadata.sourceIdentifier,
                    published: data.metadata.published,
                    lastModified: data.metadata.lastModified,
                    vulnStatus: data.metadata.vulnStatus,
                    cisaExploitAdd: data.metadata.cisaExploitAdd,
                    cisaActionDue: data.metadata.cisaActionDue,
                    cisaRequiredAction: data.metadata.cisaRequiredAction,
                    cisaVulnerabilityName: data.metadata.cisaVulnerabilityName,
                    simpleExplanation: data.analysis.simple
                };

                currentCVE = formattedData;
                addMessage({
                    type: 'bot',
                    content: `Here's the detailed information for ${inputText.toUpperCase()}:`,
                    cveData: formattedData
                });

            } catch (error) {
                console.error('API Error:', error);
                addMessage({
                    type: 'error',
                    content: `⚠️ Error: ${error.message || 'Failed to fetch CVE details'}`
                });
            }
        } else {
            addMessage({
                type: 'error',
                content: '⚠️ Please enter a valid CVE ID (format: CVE-YYYY-XXXXX)'
            });
        }

        messageInput.value = '';
        sendButton.disabled = true;
    }

    function handleInputChange() {
        sendButton.disabled = messageInput.value.trim() === '';
    }

    function addMessage({ type, content, cveData, loading }) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `flex ${type === 'user' ? 'justify-end' : 'justify-start'} message-enter`;

        let messageHTML = '';
        if (loading) {
            messageHTML = `
                <div class="max-w-3xl w-full mr-12">
                    <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                        <p class="text-sm leading-relaxed">${content}</p>
                        <div class="mt-2 flex space-x-2">
                            <div class="w-2 h-2 rounded-full bg-cyan-400 animate-bounce"></div>
                            <div class="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style="animation-delay: 0.2s"></div>
                            <div class="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style="animation-delay: 0.4s"></div>
                        </div>
                    </div>
                </div>
            `;
        }
        else if (type === 'user' || type === 'error') {
            messageHTML = `
                <div class="max-w-3xl w-full ${type === 'user' ? 'ml-12' : 'mr-12'}">
                    <div class="p-4 rounded-2xl ${type === 'user'
                    ? 'bg-gradient-to-r from-[#18392b] to-primary/30 border border-primary/30'
                    : 'bg-red-500/10 border border-red-500/30'
                } backdrop-blur-sm">
                        <p class="text-sm leading-relaxed">${content}</p>
                    </div>
                </div>
            `;
        } else {
            // Bot message with CVE data
            messageHTML = createCVEInfoMessage(content, cveData);
        }

        messageDiv.innerHTML = messageHTML;
        const insertedElement = chatContainer.insertBefore(messageDiv, messagesEnd);
        scrollToBottom();

        // Return the element for potential removal (like loading message)
        return insertedElement;
    }

    function createCVEInfoMessage(leadText, cveData) {
        return `
        <div class="max-w-3xl w-full mr-12">
            <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                <p class="text-sm leading-relaxed">${leadText}</p>
            </div>

            <!-- CVE Cards Grid -->
            <div class="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <!-- CVE ID Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">CVE ID</h3>
                        <svg class="h-4 w-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                    </div>
                    <p class="font-mono text-lg">${cveData.id}</p>
                </div>

                <!-- CVSS Score Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">CVSS Score</h3>
                        <svg class="h-4 w-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                    </div>
                    <div class="flex items-center space-x-2">
                        <span class="text-2xl font-bold">${cveData.cvssScore}</span>
                        <span class="px-2 py-1 rounded text-xs font-semibold severity-${cveData.severity.toLowerCase()} border">
                            ${cveData.severity.toUpperCase()}
                        </span>
                    </div>
                </div>

                <!-- Attack Vector Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Attack Vector</h3>
                        <svg class="h-4 w-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="2" y1="12" x2="22" y2="12"></line>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                        </svg>
                    </div>
                    <p>${cveData.attackVector}</p>
                </div>

                <!-- Exploitability Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Exploitability</h3>
                    </div>
                    <p>${cveData.exploitability}</p>
                </div>

                <!-- Privileges Required Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Privileges Required</h3>
                    </div>
                    <p>${cveData.privilegesRequired || 'N/A'}</p>
                </div>

                <!-- User Interaction Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">User Interaction</h3>
                    </div>
                    <p>${cveData.userInteraction || 'N/A'}</p>
                </div>

                <!-- Confidentiality Impact Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Confidentiality Impact</h3>
                    </div>
                    <p>${cveData.confidentialityImpact || 'N/A'}</p>
                </div>

                <!-- Integrity Impact Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Integrity Impact</h3>
                    </div>
                    <p>${cveData.integrityImpact || 'N/A'}</p>
                </div>

                <!-- Availability Impact Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Availability Impact</h3>
                    </div>
                    <p>${cveData.availabilityImpact || 'N/A'}</p>
                </div>

                <!-- Source Identifier Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Source Identifier</h3>
                    </div>
                    <p>${cveData.sourceIdentifier || 'N/A'}</p>
                </div>

                <!-- Published Date Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Published</h3>
                    </div>
                    <p>${cveData.published || 'N/A'}</p>
                </div>

                <!-- Last Modified Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Last Modified</h3>
                    </div>
                    <p>${cveData.lastModified || 'N/A'}</p>
                </div>

                <!-- Vulnerability Status Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Vulnerability Status</h3>
                    </div>
                    <p>${cveData.vulnStatus || 'N/A'}</p>
                </div>

                <!-- CISA Exploit Added Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">CISA Exploit Added</h3>
                    </div>
                    <p>${cveData.cisaExploitAdd || 'N/A'}</p>
                </div>

                <!-- CISA Action Due Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">CISA Action Due</h3>
                    </div>
                    <p>${cveData.cisaActionDue || 'N/A'}</p>
                </div>

                <!-- CISA Required Action Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">CISA Required Action</h3>
                    </div>
                    <p>${cveData.cisaRequiredAction || 'N/A'}</p>
                </div>

                <!-- CISA Vulnerability Name Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">CISA Vulnerability Name</h3>
                    </div>
                    <p>${cveData.cisaVulnerabilityName || 'N/A'}</p>
                </div>

                <!-- Affected Products Card -->
                <div class="p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Affected Products</h3>
                    </div>
                    <div class="flex flex-wrap gap-1">
                        ${cveData.affectedProducts.map(product => `
                            <span class="px-2 py-1 rounded text-xs bg-gray-800/50 border border-gray-700">
                                ${product}
                            </span>
                        `).join('')}
                    </div>
                </div>

                <!-- Description Card (Full Width) -->
                <div class="col-span-1 md:col-span-2 lg:col-span-3 p-4 rounded-2xl bg-gradient-to-r from-[#003951]/50 to-[#06373a]/30 border border-[#06373a]/30 backdrop-blur-sm">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-semibold text-primary">Description</h3>
                    </div>
                    <p class="text-sm">${cveData.description}</p>
                </div>
            </div>

            <!-- Simple Explanation -->
            <div class="mt-4 bg-gradient-to-r from-[#18392b]/40 to-[#06373a]/20 border border-primary/30 rounded-lg overflow-hidden simple-explanation-section">
                <div class="simple-header p-4 flex items-center justify-between cursor-pointer hover:bg-primary/10 transition-colors">
                    <h3 class="text-lg font-semibold text-primary flex items-center">
                        🔍 In Simple Terms
                    </h3>
                    <svg class="toggle-icon h-5 w-5 text-primary transform transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </div>
                <div class="simple-content px-4 pb-4 border-t border-primary/20">
                    <div class="mt-4 flex items-start space-x-3">
                        <div class="flex-shrink-0 mt-1">
                            <div class="w-8 h-8 bg-primary/20 rounded-full flex items-center justify-center">
                                🛡️
                            </div>
                        </div>
                        <p class="text-gray-200 leading-relaxed">
                            ${cveData.simpleExplanation}
                        </p>
                    </div>
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="mt-6 flex flex-wrap gap-3">
                <button class="copy-button bg-gradient-to-r from-primary to-[#18392b] hover:from-primary/80 hover:to-[#18392b]/80 border border-primary/30 hover:border-primary/50 text-white px-4 py-2 rounded-lg transition-all flex items-center">
                    <svg class="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                    </svg>
                    Copy Summary
                </button>
                <button class="download-button bg-transparent border border-[#06373a] hover:bg-[#06373a]/30 text-cyan-400 hover:text-cyan-300 px-4 py-2 rounded-lg transition-all flex items-center">
                    <svg class="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Download
                </button>
            </div>
        </div>
    `;
    }

    function scrollToBottom() {
        messagesEnd.scrollIntoView({ behavior: 'smooth' });
    }

    function copyToClipboard(buttonElement = null) {
        if (!currentCVE) {
            console.error('No CVE data to copy');
            return;
        }

        const text = `CVE: ${currentCVE.id}
CVSS Score: ${currentCVE.cvssScore}
Severity: ${currentCVE.severity.toUpperCase()}
Attack Vector: ${currentCVE.attackVector}
Exploitability: ${currentCVE.exploitability}

Description:
${currentCVE.description}

Affected Products: ${currentCVE.affectedProducts.join(', ')}

Privileges Required: ${currentCVE.privilegesRequired}
User Interaction: ${currentCVE.userInteraction}
Confidentiality Impact: ${currentCVE.confidentialityImpact}
Integrity Impact: ${currentCVE.integrityImpact}
Availability Impact: ${currentCVE.availabilityImpact}

Published: ${currentCVE.published}
Last Modified: ${currentCVE.lastModified}
Status: ${currentCVE.vulnStatus}

CISA Information:
- Exploit Added: ${currentCVE.cisaExploitAdd}
- Action Due: ${currentCVE.cisaActionDue}
- Required Action: ${currentCVE.cisaRequiredAction}
- Vulnerability Name: ${currentCVE.cisaVulnerabilityName}

Simple Explanation:
${currentCVE.simpleExplanation}`;

        navigator.clipboard.writeText(text).then(() => {
            // Get the specific button that was clicked, or fallback to first one
            const button = buttonElement || document.querySelector('.copy-button');
            if (button) {
                const originalText = button.innerHTML;
                button.innerHTML = `
                <svg class="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
                Copied!
            `;
                button.classList.add('bg-green-500', 'border-green-400');
                button.classList.remove('bg-gradient-to-r', 'from-primary', 'to-[#18392b]');

                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.classList.remove('bg-green-500', 'border-green-400');
                    button.classList.add('bg-gradient-to-r', 'from-primary', 'to-[#18392b]');
                }, 2000);
            }
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            alert('Failed to copy to clipboard. Please try again.');
        });
    }

    function downloadPDF() {
        if (!currentCVE) {
            console.error('No CVE data to download');
            return;
        }

        // Create a text file download
        const text = `VULNBOT - CVE ANALYSIS REPORT
=========================================

CVE: ${currentCVE.id}
Report Generated: ${new Date().toLocaleDateString()}

SUMMARY:
--------
CVSS Score: ${currentCVE.cvssScore}
Severity: ${currentCVE.severity.toUpperCase()}
Attack Vector: ${currentCVE.attackVector}
Exploitability: ${currentCVE.exploitability}

DESCRIPTION:
------------
${currentCVE.description}

TECHNICAL DETAILS:
------------------
Affected Products: ${currentCVE.affectedProducts.join(', ')}

Privileges Required: ${currentCVE.privilegesRequired}
User Interaction: ${currentCVE.userInteraction}
Confidentiality Impact: ${currentCVE.confidentialityImpact}
Integrity Impact: ${currentCVE.integrityImpact}
Availability Impact: ${currentCVE.availabilityImpact}

METADATA:
---------
Source: ${currentCVE.sourceIdentifier}
Published: ${currentCVE.published}
Last Modified: ${currentCVE.lastModified}
Status: ${currentCVE.vulnStatus}

CISA INFORMATION:
-----------------
Exploit Added: ${currentCVE.cisaExploitAdd}
Action Due: ${currentCVE.cisaActionDue}
Required Action: ${currentCVE.cisaRequiredAction}
Vulnerability Name: ${currentCVE.cisaVulnerabilityName}

SIMPLE EXPLANATION:
-------------------
${currentCVE.simpleExplanation}

=========================================
Report generated by VulnBot - Cybersecurity Assistant`;

        // Create download link
        const blob = new Blob([text], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `VulnBot-Report-${currentCVE.id}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }
});