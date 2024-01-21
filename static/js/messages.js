var flashMessages = document.getElementById('flash-messages');
if (flashMessages) {
    var flashTimeout = setTimeout(function () {
        flashMessages.classList.add('hide-flash');
    }, 5000);
    flashMessages.addEventListener('click', function () {
        clearTimeout(flashTimeout);
        flashMessages.classList.add('hide-flash');
    });
    flashMessages.classList.add('flash');
}