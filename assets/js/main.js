let themeBase;

$(document).ready(() => {
  themeBase = localStorage.getItem("themeBase") || document.getElementById("css-theme").getAttribute("href").match("-(light|dark).css")[1];
  setTheme(themeBase);
  $(document).scroll(updateHeadingOverlays);
  $(window).resize(updateHeadingOverlays);
  $("table").addClass("table table-hover");
  $("img").addClass("img img-responsive");
  $(".content-div > h1, .content-div > a > h1").addClass("h1-strip");
  setTimeout(updateHeadingOverlays, 500);
});

function updateHeadingOverlays() {
  $(".h1-overlay").remove();
  $(".h1-strip")
    .filter((index, node) => $(node).isInViewport())
    .map((index, node) => {
      let {left, top, right, bottom, x, y, width, height} = node.getBoundingClientRect();
      let style = window.getComputedStyle?getComputedStyle(node, null):node.currentStyle;
      let marginTop = parseInt(style.marginTop) || 0;
      let overlay = document.createElement("div");
      overlay.classList.add("h1-overlay");
      overlay.style.left = 0;
      overlay.style.top = `${window.scrollY+top-marginTop}px`;
      overlay.style.height = `${height+marginTop}px`;
      document.body.appendChild(overlay);
  });
}

function toggleTheme() {
  themeBase = themeBase == "light" ? "dark" : "light";
  localStorage.setItem("themeBase", themeBase);
  setTheme(themeBase);
}

function setTheme(themeBase) {
  let oldTheme = themeBase == "light" ? "dark" : "light";
  let href = document.getElementById("css-theme").getAttribute("href").replace(oldTheme, themeBase);
  let css = document.getElementById("css-theme");
  css.setAttribute("href", href);
}

// https://medium.com/talk-like/detecting-if-an-element-is-in-the-viewport-jquery-a6a4405a3ea2
$.fn.isInViewport = function() {
  var elementTop = $(this).offset().top;
  var elementBottom = elementTop + $(this).outerHeight();
  var viewportTop = $(window).scrollTop();
  var viewportBottom = viewportTop + $(window).height();
  return elementBottom > viewportTop && elementTop < viewportBottom;
};
