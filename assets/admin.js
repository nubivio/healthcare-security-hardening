(function () {
	var root = document.getElementById('nubivio-hsh');
	if (!root) {
		return;
	}
	var cb = root.querySelector('input[name="sectxt_love"]');
	var msg = document.getElementById('nhsh-love-msg');
	if (!cb || !msg) {
		return;
	}
	function update() {
		if (cb.checked) {
			msg.style.display = 'none';
			msg.textContent = '';
		} else {
			msg.style.display = 'block';
			msg.textContent = '\uD83D\uDC94 Ouch. Fine, we will keep hardening your headers in total silence. \uD83D\uDE22';
		}
	}
	cb.addEventListener('change', update);
	update();
})();
