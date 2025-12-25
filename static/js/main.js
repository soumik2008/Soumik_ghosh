document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Refresh file status every 30 seconds
    setInterval(function() {
        if (window.location.pathname === '/dashboard' || window.location.pathname === '/file_manager') {
            window.location.reload();
        }
    }, 30000);
});

// API functions for AJAX calls
function startFile(fileId) {
    fetch(`/api/start/${fileId}`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                alert('File started successfully');
                window.location.reload();
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error starting file');
        });
}

function stopFile(fileId) {
    fetch(`/api/stop/${fileId}`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                alert('File stopped successfully');
                window.location.reload();
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error stopping file');
        });
}