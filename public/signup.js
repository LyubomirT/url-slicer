document.getElementById('signupForm').addEventListener('submit', function (event) {
    event.preventDefault();
    const username = document.getElementById('usernameInput').value;
    const password = document.getElementById('passwordInput').value;

    fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
    })
        .then((response) => response.text())
        .then((tokenContent) => {
            const blob = new Blob([tokenContent], { type: 'text/plain' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'token.txt';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        })
        .catch((error) => {
            console.error('Error:', error);
        });
});