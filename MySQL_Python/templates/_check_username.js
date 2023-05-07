function checkUsername() {
  const usernameInput = document.getElementsByName('username')[0];
  const username = usernameInput.value;

  // Perform an AJAX request to check if the username already exists
  fetch('/check_username', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: `username=${encodeURIComponent(username)}`,
  }).then(function(response) {
    return response.json();
  }).then(function(data) {
    if (data.exists) {
      alert('The username is already taken. Please choose another one.');
      usernameInput.value = '';
      usernameInput.focus();
    }
  });
}

// Attach the checkUsername function to the username input field
document.getElementsByName('username')[0].addEventListener('change', checkUsername);
