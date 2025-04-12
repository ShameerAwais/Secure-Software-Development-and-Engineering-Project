console.log("Content script loaded"),chrome.runtime.onMessage.addListener(((e,o,n)=>("checkUrl"===e.type&&n({url:window.location.href}),!0)));
//# sourceMappingURL=content.bundle.js.map