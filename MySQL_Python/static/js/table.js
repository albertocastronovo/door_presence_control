let currentPage = 1;
let totalPages;
let currentFilters = {};
let currentOrderBy;

function updateTable() {
  const perPage = parseInt(document.getElementById('rows-per-page').value);
  const url = new URL('/users_for_table', window.location.origin);

  url.searchParams.append('page', currentPage);
  url.searchParams.append('per_page', perPage);

  if (Object.keys(currentFilters).length > 0) {
    url.searchParams.append('filters', JSON.stringify(currentFilters));
  }

  if (currentOrderBy) {
    url.searchParams.append('order_by', currentOrderBy);
  }

  fetch(url)
    .then(response => response.json())
    .then(data => {
      const tableBody = document.getElementById('user-table').getElementsByTagName('tbody')[0];
      tableBody.innerHTML = '';

      data.users.forEach(user => {
        const row = tableBody.insertRow();
        Object.keys(user).forEach(key => {
          const cell = row.insertCell();
          cell.textContent = user[key];
        });
      });

      document.getElementById('current-page').textContent = currentPage;
      document.getElementById('total-pages').textContent = data.total_pages;
      totalPages = data.total_pages;
    });
}

document.getElementById('filter-form').addEventListener('submit', event => {
  event.preventDefault();

  currentFilters = {
    email: document.getElementById('email').value,
    name: document.getElementById('name').value,
    surname: document.getElementById('surname').value,
    username: document.getElementById('username').value,
    gender: document.getElementById('gender').value,
    birth_date: document.getElementById('birth_date').value,
  };

  currentPage = 1;
  updateTable();
});

document.getElementById('rows-per-page').addEventListener('change', () => {
  currentPage = 1;
  updateTable();
});

document.getElementById('previous-page').addEventListener('click', () => {
  if (currentPage > 1) {
    currentPage--;
    updateTable();
  }
});

document.getElementById('next-page').addEventListener('click', () => {
  if (currentPage < totalPages) {
    currentPage++;
    updateTable();
  }
});

// Add event listeners for sorting columns
['name', 'surname', 'birth_date'].forEach(column => {
  document.getElementById(column).addEventListener('click', () => {
    currentOrderBy = currentOrderBy === column ? `-${column}` : column;
    currentPage = 1;
    updateTable();
  });
});

updateTable();