document.getElementById('loginForm').addEventListener('submit', function (event) {
    event.preventDefault();

    const data = new URLSearchParams(new FormData(event.target)).toString();

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: data,
    })
        .then((response) => {
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                alert('Invalid credentials');
            }
        })
        .catch((error) => {
            console.error('Error:', error);
        });
});