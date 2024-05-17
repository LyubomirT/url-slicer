document.getElementById('urlForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const url = document.getElementById('urlInput').value;
    const expiry = document.getElementById('expiryInput').value;
    const maxUses = document.getElementById('maxUsesInput').value;

    fetch('/api/shorten', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url, expiry, maxUses })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').innerHTML = 'Shortened URL: ' + data.url;
    })
    .catch(error => {
        document.getElementById('response').innerHTML = 'Error: ' + error;
    });
});
