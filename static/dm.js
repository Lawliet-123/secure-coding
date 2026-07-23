// [보안] 대화 상대 ID는 JSON 스크립트 블록에서 안전하게 읽고, 출력은 textContent 사용
const partnerId = JSON.parse(document.getElementById('dmdata').textContent);
const socket = io();
const box = document.getElementById('dmbox');
const form = document.getElementById('dmform');
const input = document.getElementById('dmmsg');

socket.on('connect', () => socket.emit('join_dm', { partner_id: partnerId }));

socket.on('dm_message', (data) => {
  const p = document.createElement('p');
  const b = document.createElement('b');
  b.textContent = data.username + ': ';
  p.appendChild(b);
  p.appendChild(document.createTextNode(data.message));
  box.appendChild(p);
  box.scrollTop = box.scrollHeight;
});

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const v = input.value.trim();
  if (!v) return;
  socket.emit('send_dm', { partner_id: partnerId, message: v });
  input.value = '';
});
