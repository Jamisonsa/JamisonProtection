function loginUser(event) {
  event.preventDefault();
  const user = document.getElementById('username').value;
  const pass = document.getElementById('password').value;

  if (user === 'admin' && pass === 'ownerpass') {
    window.location.href = 'owner-panel.html';
  } else if (user === 'worker1' && pass === 'secure123') {
    window.location.href = 'worker-dashboard.html';
  } else {
    document.getElementById('login-error').textContent = 'Invalid credentials.';
  }
}
 
