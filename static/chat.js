// [보안] innerHTML 대신 textContent 사용 → 저장형/반사형 XSS 방어
const socket = io();
const chat = document.getElementById('chat');
const form = document.getElementById('chatform');
const input = document.getElementById('msg');

socket.on('message', (data) => {
  const p = document.createElement('p');
  const b = document.createElement('b');
  b.textContent = data.username + ': ';
  p.appendChild(b);
  p.appendChild(document.createTextNode(data.message));
  chat.appendChild(p);
  chat.scrollTop = chat.scrollHeight;
});

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const v = input.value.trim();
  if (!v) return;
  socket.emit('send_message', { message: v });
  input.value = '';
});
