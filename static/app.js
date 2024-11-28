function render_items(data){
    data = JSON.parse(data)
    data.forEach(e=>{
        console.log(e)
        var marker = L.marker(e.coords).addTo(map)
        marker.bindPopup(e.popup)
    })

}



document.addEventListener("DOMContentLoaded", () => {
  const button = document.getElementById("profile-btn");
  const dropdown = document.getElementById("dropdown-menu");
  const dropdownArrow = document.getElementById("dropdown-arrow"); // Add reference to the arrow

  button.addEventListener("click", () => {
    dropdown.classList.toggle("show");

    // Toggle the arrow direction
    if (dropdown.classList.contains("show")) {
      dropdownArrow.innerHTML = "&#x2191;"; // Up arrow
    } else {
      dropdownArrow.innerHTML = "&#x2193;"; // Down arrow
    }
  });

  // Optional: Close the dropdown when clicking outside
  document.addEventListener("click", (event) => {
    if (!button.contains(event.target) && !dropdown.contains(event.target)) {
      dropdown.classList.remove("show");

      // Reset arrow to down when dropdown closes
      dropdownArrow.innerHTML = "&#x2193;";
    }
  });
});


  // Function to preview the image before uploading
  function previewImage(event) {
    const file = event.target.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
      // Set the preview image to the selected file
      const imagePreview = document.getElementById('profile-preview');
      imagePreview.src = e.target.result;
    };

    if (file) {
      reader.readAsDataURL(file);  // Convert the image file to a data URL
    }
  }