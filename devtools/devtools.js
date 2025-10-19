browser.devtools.panels.create(
  "Enhanced Network Tab",
  "/icons/icon32.png",
  "/devtools/panel.html"
).then((panel) => {
  console.log("Enhanced Network Tab panel created");
}).catch((error) => {
  console.error("Error creating panel:", error);
});