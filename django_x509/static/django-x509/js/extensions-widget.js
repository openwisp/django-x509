(function () {
  "use strict";

  function createElement(tagName, className, text) {
    var element = document.createElement(tagName);
    if (className) {
      element.className = className;
    }
    if (typeof text !== "undefined") {
      element.textContent = text;
    }
    return element;
  }

  function getValueSchema(option) {
    return option.branch.properties.value;
  }

  function parseOptions(schema) {
    var branches = ((schema || {}).items || {}).oneOf || [],
      options = [],
      unsupported = false;

    branches.forEach(function (branch) {
      var properties = branch.properties || {},
        name = properties.name && properties.name.const,
        valueSchema = properties.value || {},
        supportedValueSchema =
          valueSchema.type === "string" ||
          (valueSchema.type === "array" &&
            valueSchema.items &&
            Array.isArray(valueSchema.items.enum));
      if (!name || !supportedValueSchema) {
        unsupported = true;
        return;
      }
      options.push({
        name: name,
        label: branch.title || name,
        description: branch.description || valueSchema.description || "",
        branch: branch,
      });
    });

    if (unsupported || !options.length) {
      return null;
    }
    return options;
  }

  function getDefaultValue(valueSchema) {
    if (valueSchema.type === "array") {
      return [];
    }
    return "";
  }

  function normalizeItems(rawItems, optionMap) {
    var items;
    if (!Array.isArray(rawItems)) {
      return null;
    }
    items = rawItems.map(function (item) {
      var hasCritical, option, valueSchema, normalized;
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        return null;
      }
      option = optionMap[item.name];
      if (!option) {
        return null;
      }
      valueSchema = getValueSchema(option);
      hasCritical = Object.prototype.hasOwnProperty.call(item, "critical");
      if (hasCritical && typeof item.critical !== "boolean") {
        return null;
      }
      normalized = {
        name: item.name,
        critical: hasCritical ? item.critical : false,
        value: item.value,
      };
      if (valueSchema.type === "array") {
        if (typeof normalized.value === "string") {
          normalized.value = normalized.value
            .split(",")
            .map(function (value) {
              return value.trim();
            })
            .filter(Boolean);
        }
        if (
          !Array.isArray(normalized.value) ||
          normalized.value.some(function (value) {
            return typeof value !== "string";
          })
        ) {
          return null;
        }
      } else if (typeof normalized.value !== "string") {
        return null;
      }
      return normalized;
    });
    return items.indexOf(null) > -1 ? null : items;
  }

  function syncTextarea(textarea, items) {
    textarea.value = JSON.stringify(items, null, 2);
  }

  function buildArrayValueEditor(rowBody, item, option, onChange) {
    var wrapper = createElement("div", "x509-extensions-choice-list"),
      valueSchema = getValueSchema(option);

    valueSchema.items.enum.forEach(function (choice) {
      var label = createElement("label", "x509-extensions-choice"),
        checkbox = createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = choice;
      checkbox.checked = item.value.indexOf(choice) > -1;
      checkbox.addEventListener("change", function () {
        item.value = Array.prototype.slice
          .call(wrapper.querySelectorAll("input:checked"))
          .map(function (element) {
            return element.value;
          });
        onChange();
      });
      label.appendChild(checkbox);
      label.appendChild(document.createTextNode(" " + choice));
      wrapper.appendChild(label);
    });

    rowBody.appendChild(wrapper);
  }

  function buildStringValueEditor(rowBody, item, option, onChange) {
    var input = createElement("input", "vTextField x509-extensions-input"),
      valueSchema = getValueSchema(option);

    input.type = "text";
    input.value = item.value;
    if (valueSchema.maxLength) {
      input.maxLength = valueSchema.maxLength;
    }
    input.addEventListener("input", function () {
      item.value = input.value;
      onChange();
    });
    rowBody.appendChild(input);
  }

  function renderRow(editor, items, options, optionMap, index, onChange, labels) {
    var item = items[index],
      option = optionMap[item.name],
      valueSchema = getValueSchema(option),
      row = createElement("div", "x509-extensions-row"),
      header = createElement("div", "x509-extensions-row__header"),
      selectWrap = createElement("label", "x509-extensions-row__field"),
      selectLabel = createElement("span", "x509-extensions-row__label", "Extension"),
      select = createElement("select", "x509-extensions-select"),
      criticalWrap = createElement("label", "x509-extensions-row__field"),
      critical = createElement("input"),
      removeButton = createElement(
        "button",
        "button x509-extensions-remove",
        labels.remove,
      ),
      rowBody = createElement("div", "x509-extensions-row__body"),
      valueLabel = createElement(
        "span",
        "x509-extensions-row__label",
        valueSchema.title || "Value",
      );

    options.forEach(function (selectOption) {
      var optionElement = createElement("option");
      optionElement.value = selectOption.name;
      optionElement.textContent = selectOption.label;
      optionElement.selected = selectOption.name === item.name;
      select.appendChild(optionElement);
    });

    select.addEventListener("change", function () {
      var nextOption = optionMap[select.value];
      item.name = nextOption.name;
      item.value = getDefaultValue(getValueSchema(nextOption));
      onChange();
    });

    critical.type = "checkbox";
    critical.checked = item.critical;
    critical.addEventListener("change", function () {
      item.critical = critical.checked;
      onChange();
    });

    removeButton.type = "button";
    removeButton.addEventListener("click", function () {
      items.splice(index, 1);
      onChange();
    });

    selectWrap.appendChild(selectLabel);
    selectWrap.appendChild(select);
    criticalWrap.appendChild(document.createTextNode("Critical "));
    criticalWrap.appendChild(critical);
    header.appendChild(selectWrap);
    header.appendChild(criticalWrap);
    header.appendChild(removeButton);
    row.appendChild(header);

    if (option.description) {
      row.appendChild(
        createElement("p", "help x509-extensions-row__description", option.description),
      );
    }

    rowBody.appendChild(valueLabel);
    if (valueSchema.type === "array") {
      buildArrayValueEditor(rowBody, item, option, onChange);
    } else {
      buildStringValueEditor(rowBody, item, option, onChange);
    }
    row.appendChild(rowBody);
    editor.appendChild(row);
  }

  function renderEditor(widget, textarea, editor, items, options, optionMap, labels) {
    editor.innerHTML = "";

    items.forEach(function (_item, index) {
      renderRow(
        editor,
        items,
        options,
        optionMap,
        index,
        function () {
          syncTextarea(textarea, items);
          renderEditor(widget, textarea, editor, items, options, optionMap, labels);
        },
        labels,
      );
    });

    var addButton = createElement("button", "button x509-extensions-add", labels.add);
    addButton.type = "button";
    addButton.addEventListener("click", function () {
      items.push({
        name: options[0].name,
        critical: false,
        value: getDefaultValue(getValueSchema(options[0])),
      });
      syncTextarea(textarea, items);
      renderEditor(widget, textarea, editor, items, options, optionMap, labels);
    });
    editor.appendChild(addButton);
  }

  function showMessage(widget, text) {
    var message = widget.querySelector(".x509-extensions-widget__message");
    message.hidden = false;
    message.textContent = text;
  }

  function initWidget(widget) {
    var editor = widget.querySelector(".x509-extensions-editor"),
      textarea = widget.querySelector("textarea"),
      details = widget.querySelector(".x509-extensions-raw"),
      schema,
      options,
      optionMap = {},
      items,
      labels = {
        add: widget.dataset.addLabel || "Add extension",
        remove: widget.dataset.removeLabel || "Remove",
      };

    try {
      schema = JSON.parse(widget.dataset.schema || "{}");
    } catch (error) {
      details.open = true;
      showMessage(widget, widget.dataset.unsupportedLabel);
      return;
    }

    options = parseOptions(schema);
    if (!options) {
      details.open = true;
      showMessage(widget, widget.dataset.unsupportedLabel);
      return;
    }
    options.forEach(function (option) {
      optionMap[option.name] = option;
    });

    try {
      items = textarea.value.trim() ? JSON.parse(textarea.value) : [];
    } catch (error) {
      details.open = true;
      showMessage(widget, widget.dataset.invalidJsonLabel);
      return;
    }

    items = normalizeItems(items, optionMap);
    if (!items) {
      details.open = true;
      showMessage(widget, widget.dataset.invalidJsonLabel);
      return;
    }

    renderEditor(widget, textarea, editor, items, options, optionMap, labels);
  }

  document.addEventListener("DOMContentLoaded", function () {
    Array.prototype.forEach.call(
      document.querySelectorAll(".x509-extensions-widget"),
      initWidget,
    );
  });
})();
