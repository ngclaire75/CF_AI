// CF_AI Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const userInput = document.getElementById('user-input');
    const sendButton = document.getElementById('send-button');
    const chatMessages = document.getElementById('chat-messages');
    const statusInfo = document.getElementById('status-info');

    // Load system status on page load
    loadSystemStatus();

    // Send message on button click
    sendButton.addEventListener('click', sendMessage);

    // Send message on Enter key
    userInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    function sendMessage() {
        const message = userInput.value.trim();
        if (message === '') return;

        // Add user message to chat
        addMessage('user', message);
        userInput.value = '';

        // Send to API
        fetch('/api/command', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                command: message,
                timeout: 30
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                addMessage('ai', `Command executed successfully:\n${data.output}`);
            } else {
                addMessage('ai', `Error: ${data.error}`);
            }
        })
        .catch(error => {
            addMessage('ai', `Network error: ${error.message}`);
        });
    }

    function addMessage(sender, content) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;

        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';

        if (sender === 'ai') {
            contentDiv.innerHTML = `<strong>CF_AI:</strong> ${content.replace(/\n/g, '<br>')}`;
        } else {
            contentDiv.innerHTML = `<strong>You:</strong> ${content}`;
        }

        messageDiv.appendChild(contentDiv);
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function loadSystemStatus() {
        fetch('/health')
        .then(response => response.json())
        .then(data => {
            statusInfo.innerHTML = `
                <p><strong>Status:</strong> ${data.status}</p>
                <p><strong>Version:</strong> ${data.version}</p>
                <p><strong>Tools Available:</strong> ${data.total_tools_available}/${data.total_tools_count}</p>
                <p><strong>Uptime:</strong> ${Math.floor(data.uptime / 60)} minutes</p>
                <p><strong>Essential Tools:</strong> ${data.all_essential_tools_available ? 'All Available' : 'Some Missing'}</p>
            `;
        })
        .catch(error => {
            statusInfo.innerHTML = `<p>Error loading status: ${error.message}</p>`;
        });
    }

    function showCategory(category) {
        // This could be expanded to show tools in each category
        addMessage('ai', `Showing tools in category: ${category}`);
    }

    // Auto-refresh status every 30 seconds
    setInterval(loadSystemStatus, 30000);
});