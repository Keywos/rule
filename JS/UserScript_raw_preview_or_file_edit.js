// ==UserScript==
// @name         GitHub Raw Link Opener / Script-Hub edit
// @namespace    GitHub / Script-Hub
// @version      3.1.0
// @description  增强 GitHub 的原始链接按钮。一键编辑 Script-Hub 生成的链接
// @author       baby,小一,Key
// @match        https://github.com/*
// @match        https://script.hub/file/*
// @match        http://script.hub/file/*
// @match        https://script.hub/convert/*
// @match        http://script.hub/convert/*
// @match        http://127.0.0.1:9101/file/*
// @match        http://127.0.0.1:9101/convert/*
// ==/UserScript==
(function () {
  "use strict";
  /\/blob\//.test(window.location.pathname) && init();
  /\/(file|convert)\//.test(window.location.pathname) && initeh();

  function init() {
    const rawButton = createButton("打开 Raw", openRawLink);
    document.body.appendChild(rawButton);

    const rawViewButton = createButton("打开 Code Hub", openRawHiLink);
    document.body.appendChild(rawViewButton);

    const scriptHubButton = createButton("打开 ScriptHub", openScriptHubLink);
    document.body.appendChild(scriptHubButton);
  }

  function initeh() {
    const scriptHubEdit = createButton("打开 Script-Hub 编辑", reEditLink);
    document.body.appendChild(scriptHubEdit);
  }

  function createButton(text, clickHandler) {
    const button = document.createElement("button");
    const buttonStyle = {
      position: "fixed",
      backgroundColor: "#303033ab",
      color: "#eeeeee",
      border: "none",
      padding: "4px 12px",
      borderRadius: "14px",
      cursor: "pointer",
      fontSize: "10px",
    };
    button.innerHTML = text;
    Object.assign(button.style, buttonStyle);

    if (text === "打开 Raw") {
      button.style.right = "10px";
      button.style.bottom = "80px";
    }

    if (text === "打开 Code Hub") {
      button.style.right = "10px";
      button.style.bottom = "50px";
    }

    if (text === "打开 ScriptHub") {
      button.style.left = "10px";
      button.style.bottom = "50px";
    }

    if (text === "打开 Script-Hub 编辑") {
      button.style.right = "10px";
      button.style.bottom = "50px";
    }

    button.addEventListener("click", clickHandler);
    return button;
  }

  function getRawUrl() {
    return window.location.href
      .replace("/blob", "")
      .replace("github.com", "raw.githubusercontent.com");
  }

  function openRawLink() {
    window.open(getRawUrl(), "_blank");
  }

  function openRawHiLink() {
    const Url =
      "https://app.linkey.store/EditCode?" + encodeURIComponent(getRawUrl());
    window.open(Url, "_blank");
  }

  function reEditLink() {
    const Url = window.location.href.replace(/\/(convert|file)\//, "/edit/");
    window.open(Url, "_blank");
  }

  function openScriptHubLink() {
    const scriptHubUrl = `http://script.hub/convert/_start_/${getRawUrl()}/_end_/plain.txt?type=plain-text&target=plain-text`;
    window.open(scriptHubUrl, "_blank");
  }
})();
