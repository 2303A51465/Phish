const historyBody = document.getElementById('history-body');
const historyRefresh = document.getElementById('history-refresh');
const clearAllBtn = document.getElementById('clear-all-btn');
const emptyMessage = document.getElementById('empty-message');

function renderHistory(rows) {
  if (!rows || rows.length === 0) {
    historyBody.innerHTML = '';
    emptyMessage.classList.remove('hidden');
    clearAllBtn.classList.add('hidden');
    return;
  }

  emptyMessage.classList.add('hidden');
  clearAllBtn.classList.remove('hidden');
  historyBody.innerHTML = rows.map((item, index) => {
    const statusClass = item.status === 'Phishing' ? 'status-phishing' : 'status-safe';
    return `
      <tr data-id="${item.id}">
        <td>${new Date(item.date_checked).toLocaleString()}</td>
        <td><a href="${item.url}" target="_blank" rel="noreferrer noopener" title="${item.url}">${item.url}</a></td>
        <td class="${statusClass}">${item.status}</td>
        <td>${item.risk_score}%</td>
        <td><button class="delete-btn" data-id="${item.id}" type="button">Delete</button></td>
      </tr>
    `;
  }).join('');

  document.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', deleteRecord);
  });
}

async function deleteRecord(event) {
  const recordId = event.target.dataset.id;
  const row = event.target.closest('tr');

  if (!confirm('Are you sure you want to delete this record?')) return;

  try {
    const response = await fetch(`/delete_history/${recordId}`, {
      method: 'DELETE',
    });

    if (!response.ok) throw new Error('Failed to delete record');
    row.remove();
    
    if (historyBody.children.length === 0) {
      renderHistory([]);
    }
  } catch (error) {
    alert('Error deleting record: ' + error.message);
  }
}

async function clearAllHistory() {
  if (!confirm('Are you sure you want to delete ALL history? This cannot be undone.')) return;

  try {
    const response = await fetch('/delete_all_history', {
      method: 'DELETE',
    });

    if (!response.ok) throw new Error('Failed to clear history');
    renderHistory([]);
  } catch (error) {
    alert('Error clearing history: ' + error.message);
  }
}

async function fetchHistory() {
  try {
    const response = await fetch('/history');
    if (!response.ok) throw new Error('Unable to load history');
    const result = await response.json();
    renderHistory(result.history);
  } catch (error) {
    historyBody.innerHTML = `<tr><td colspan="5">Error loading history: ${error.message}</td></tr>`;
  }
}

historyRefresh.addEventListener('click', fetchHistory);
clearAllBtn.addEventListener('click', clearAllHistory);
window.addEventListener('DOMContentLoaded', fetchHistory);
