document.addEventListener('DOMContentLoaded', function() {
  const sidebar = document.querySelector(".sidebar");
  const closeBtn = document.querySelector("#btn");
  const manageProjectsLink = document.getElementById('manageProjects');
  const addProjectBtn = document.getElementById('addProjectBtn');
  const modal = document.getElementById('myModal');

  // Toggle sidebar open/close on logo click
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open");
      menuBtnChange();
    });
  }

  if (manageProjectsLink) {
    manageProjectsLink.addEventListener('click', function(event) {
      event.preventDefault();
      addProjectBtn.style.display = 'block';
    });
  }

  function menuBtnChange() {
    if (sidebar.classList.contains("open")) {
      closeBtn.classList.replace("bx-menu", "bx-menu-alt-right");
    } else {
      closeBtn.classList.replace("bx-menu-alt-right", "bx-menu");
    }
  }

  if (addProjectBtn) {
    addProjectBtn.addEventListener('click', function() {
      $('#myModal').modal('show');
    });
  }

  $('#userLink').on('click', function () {
    $('#userDetailsModal').modal('show');
});

$('#changePasswordBtn').on('click', function () {
    $('#userDetailsModal').modal('hide');
    $('#changePasswordModal').modal('show');
});

  window.addEventListener('click', function(event) {
    if (event.target === modal) {
      $('#myModal').modal('hide');
    }
  });

  const navLinks = document.querySelectorAll('.navlink');

    function handleNavLinkClick(event) {
        navLinks.forEach(link => link.classList.remove('active'));

        event.currentTarget.classList.add('active');
    }

    navLinks.forEach(link => {
        link.addEventListener('click', handleNavLinkClick);
    });
});
