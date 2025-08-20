// Function to toggle Box D visibility
function toggleBoxDVisibility() {
    const boxD = document.getElementById('box-d');
    const logsDiv = document.getElementById('logs');
    const logCount = logsDiv.children.length;
    if (logCount > 0) {
        boxD.classList.add('visible');
    } else {
        boxD.classList.remove('visible');
    }
}

// Search calculators by name, domain, or input labels
function searchCalculators() {
    const query = document.getElementById('search-box').value.toLowerCase();
    const resultsDiv = document.getElementById('search-results');
    resultsDiv.innerHTML = '';

    if (query.trim() === '') {
        resultsDiv.classList.remove('visible');
        return;
    }

    const matchedCalculators = [];

    Object.entries(calculators).forEach(([calcId, calc]) => {
        const nameMatch = calc.title.toLowerCase().includes(query);
        const domainMatch = calc.domain.toLowerCase().includes(query);

        if (nameMatch || domainMatch) {
            matchedCalculators.push({ calcId, calc, matchedBy: nameMatch ? 'name' : 'domain' });
        }

        calc.inputs.forEach(input => {
            if (input.label.toLowerCase().includes(query)) {
                matchedCalculators.push({ calcId, calc, matchedBy: `label: ${input.label}` });
            }
        });
    });

    if (matchedCalculators.length === 0) {
        resultsDiv.innerHTML = '<div class="result-item"><span class="calc-name">No results found</span></div>';
        resultsDiv.classList.add('visible');
        return;
    }

    matchedCalculators.forEach(({ calcId, calc, matchedBy }) => {
        const resultItem = document.createElement('div');
        resultItem.className = 'result-item';
        resultItem.innerHTML = `
            <span class="calc-name">${calc.title}</span>
            <span class="calc-domain">${calc.domain}${matchedBy.startsWith('label') ? ` (${matchedBy})` : ''}</span>
        `;
        resultItem.onclick = () => {
            document.getElementById('search-box').value = '';
            resultsDiv.classList.remove('visible');
            showCalculator(calcId);
        };
        resultsDiv.appendChild(resultItem);
    });

    resultsDiv.classList.add('visible');
}

// Filter calculators by domain and display in Box B
function filterCalculators(domain) {
    const buttons = document.querySelectorAll('#box-e button');
    buttons.forEach(btn => {
        btn.classList.remove('active');
        if (btn.textContent === domain) {
            btn.classList.add('active');
        }
    });

    let filteredCalcs;
    if (domain === 'All Domains') {
        filteredCalcs = Object.keys(calculators);
    } else {
        filteredCalcs = Object.keys(calculators).filter(calcId => calculators[calcId].domain === domain);
    }

    const calcList = document.getElementById('calculator-list');
    calcList.innerHTML = '';
    filteredCalcs.forEach(calcId => {
        const calc = calculators[calcId];
        const li = document.createElement('li');
        li.textContent = calc.title;
        li.onclick = () => showCalculator(calcId);
        calcList.appendChild(li);
    });

    const calcListItems = document.querySelectorAll('#calculator-list li');
    calcListItems.forEach(item => item.classList.remove('selected'));

    if (domain === 'All Domains') {
        fetch('calculator_welcome.html')
            .then(response => response.text())
            .then(data => {
                document.getElementById('calculator-content').innerHTML = data;
                toggleBoxDVisibility();
                history.pushState({}, '', '/');
            })
            .catch(error => {
                document.getElementById('calculator-content').innerHTML = '<p>Error loading welcome section.</p>';
            });
    }
}

// Show pop-up
function showPopup() {
    const calcId = document.getElementById('calculator-content').querySelector('form')?.id?.replace('-form', '');
    const popupText = calculators[calcId]?.popupText || 'Welcome to the Calculator Hub! Select a calculator from the list to get started.';
    const formattedText = popupText.replace(/\n/g, '<br>');
    const popupContent = document.getElementById('popup-text');
    popupContent.innerHTML = formattedText;
    const popup = document.getElementById('popup');
    popup.style.display = 'block';
    setTimeout(() => {
        popup.querySelector('.popup-content').classList.add('show');
    }, 10);
}

// Close pop-up
function closePopup() {
    const popup = document.getElementById('popup');
    const popupContent = popup.querySelector('.popup-content');
    popupContent.classList.remove('show');
    setTimeout(() => {
        popup.style.display = 'none';
    }, 300);
}

// ✅ Updated to use local server endpoint
// Updated runCalculator function
async function runCalculator(calcId) {
    if (calcId in calculators) {
        const calc = calculators[calcId];
        let inputValues = {};

        // Validate inputs
        const validationErrors = validateInputs(calcId);
        if (validationErrors.length > 0) {
            showModal(validationErrors.join('\n'));
            return;
        }

        // Collect input values as a dictionary
        if (calc.subjectMappings) {
            const selectorId = calc.inputs[0].id;
            const numItems = document.getElementById(selectorId)?.value;
            inputValues['channel_type'] = numItems; // Include channel type as a key

            const numItemsInt = parseInt(numItems);
            if (calc.subjectMappings && calc.subjectMappings[numItemsInt]) {
                calc.subjectMappings[numItemsInt].forEach(input => {
                    const element = document.getElementById(input.id);
                    if (input.type === 'text') {
                        inputValues[input.id] = input.optional && !element?.value ? null : element?.value || '';
                    } else if (input.type === 'dropdown') {
                        inputValues[input.id] = element?.value || '';
                    } else if (input.type === 'radio-group') {
                        const selectedValue = document.querySelector(`input[name="${input.groupName}"]:checked`)?.value || '';
                        inputValues[input.id] = selectedValue;
                    } else if (input.type === 'checkbox') {
                        inputValues[input.id] = element.checked ? 'true' : 'false';
                    }
                });
            }
        } else {
            inputValues = calc.inputs
                .filter(input => !input.hidden)
                .reduce((obj, input) => {
                    const element = document.getElementById(input.id);
                    obj[input.id] = input.type === 'checkbox' ? (element.checked ? 'true' : 'false') : element.value;
                    return obj;
                }, {});
        }

        try {
            const response = await fetch('http://localhost:5000/calculate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    calculator: calcId,
                    data: inputValues // Send as 'data' object instead of 'numbers'
                })
            });

            const data = await response.json();
            document.getElementById('output').innerText = `Output: ${data.result}`;

            if (data.logs) {
                data.logs.forEach(log => logToBoxD(log));
            }

        } catch (error) {
            document.getElementById('output').innerText = `Error: Failed to connect to the server.`;
            logToBoxD(`Error: ${error.message}`);
        }
    }
}
// Log messages to Box D
function logToBoxD(message) {
    const logsDiv = document.getElementById('logs');
    const maxLogs = 50;
    const logEntries = logsDiv.getElementsByTagName('p');

    logsDiv.innerHTML += `<p>${message}</p>`;

    if (logEntries.length > maxLogs) {
        logsDiv.removeChild(logEntries[0]);
    }

    logsDiv.scrollTop = logsDiv.scrollHeight;

    const boxD = document.getElementById('box-d');
    boxD.classList.add('visible');
}

// Clear logs in Box D
function clearLogs() {
    const logsDiv = document.getElementById('logs');
    logsDiv.innerHTML = '';
    toggleBoxDVisibility();
}

// Handle browser back/forward navigation
window.onpopstate = (event) => {
    const state = event.state;
    if (state && state.calcId) {
        showCalculator(state.calcId);
    } else {
        filterCalculators('All Domains');
    }
};