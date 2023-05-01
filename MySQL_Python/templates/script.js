document.getElementById('auth-form').addEventListener('submit', function(event) {
event.preventDefault();

// Fetch data from the form
const formData = new FormData(event.target);
const username = formData.get('username');
const password = formData.get('password');

// Perform an AJAX request to check the user's credentials
fetch('/check_auth', {
  method: 'POST',
  body: formData,
}).then(function(response) {
  if (response.ok) {
    // Unhide the new form if the authentication was successful
    document.getElementById('details-form').style.display = 'block';
  } else {
    // Handle unsuccessful authentication
    alert('Invalid username or password');
  }
});
});
