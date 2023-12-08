document.addEventListener("DOMContentLoaded", function() {
    const linkForm = document.getElementById("link-checker-form");
    if (linkForm) {
        linkForm.addEventListener("submit", function(event) {
            event.preventDefault();
            const url = document.getElementById("link").value;

            fetch('/check_link', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            })
            .then(response => response.json())
            .then(data => {
                window.location.href = '/result';
            })
            .catch((error) => {
                console.error('Error:', error);
            });
        });
    }
});
