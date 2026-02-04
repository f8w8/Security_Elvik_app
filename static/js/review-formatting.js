// JavaScript for interactive star rating system

// Get all the rating elements
var ratingInputs = document.querySelectorAll('input[name="rating"]');
var starLabels = document.querySelectorAll('.star-label');
var stars = document.querySelectorAll('.star');
var ratingText = document.getElementById('rating-text');

// Text labels for each rating level
var labels = ['Poor', 'Fair', 'Good', 'Very Good', 'Excellent'];

// Function to update star colors based on selected rating
function updateStarDisplay() {
    var checkedInput = document.querySelector('input[name="rating"]:checked');
    var selectedRating = checkedInput ? parseInt(checkedInput.value) : 0;

    // Color stars yellow up to selected rating, gray after
    stars.forEach(function (star, index) {
        if (index < selectedRating) {
            star.style.color = '#ffc107';
        } else {
            star.style.color = '#ddd';
        }
    });

    // Show text label for rating (Poor, Fair, Good, etc)
    if (selectedRating > 0) {
        ratingText.textContent = labels[selectedRating - 1];
    } else {
        ratingText.textContent = '';
    }
}

// Listen for when user clicks a star
ratingInputs.forEach(function (input, index) {
    input.addEventListener('change', function () {
        updateStarDisplay();
    });
});

// Show yellow stars on hover to give visual feedback
starLabels.forEach(function (label, labelIndex) {
    label.addEventListener('mouseenter', function () {
        stars.forEach(function (star, starIndex) {
            if (starIndex <= labelIndex) {
                star.style.color = '#ffc107';
            } else {
                star.style.color = '#ddd';
            }
        });
    });

    // Reset to actual selection when mouse leaves
    label.addEventListener('mouseleave', function () {
        updateStarDisplay();
    });
});

// Show current rating when page loads (if editing existing review)
updateStarDisplay();

// Character counter for review text
var content = document.getElementById('content');
var charCount = document.getElementById('char-count');

// Update character count as user types
function updateCharCount() {
    charCount.textContent = content.value.length;
}

// Listen for typing in the textarea
content.addEventListener('input', updateCharCount);
// Set initial count on page load
updateCharCount();

// Simple markdown to HTML converter for live preview
function markdownToHtml(text) {
    if (!text || text.trim() === '') {
        return '<span class="preview-empty">Your formatted review will appear here...</span>';
    }

    var html = text;

    // Escape HTML to prevent XSS
    html = html.replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    // Convert bold **text** to <strong>text</strong>
    html = html.replace(/\*\*([^\*]+)\*\*/g, '<strong>$1</strong>');

    // Convert italic *text* to <em>text</em> (but not if it's part of **)
    html = html.replace(/\*([^\*]+)\*/g, '<em>$1</em>');

    // Split by lines for list processing
    var lines = html.split('\n');
    var result = [];
    var inList = false;
    var listType = null;

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];

        // Check for bullet list
        if (line.match(/^-\s+(.+)/)) {
            if (!inList || listType !== 'ul') {
                if (inList) {
                    result.push(listType === 'ul' ? '</ul>' : '</ol>');
                }
                result.push('<ul>');
                inList = true;
                listType = 'ul';
            }
            result.push('<li>' + line.replace(/^-\s+/, '') + '</li>');
        }
        // Check for numbered list
        else if (line.match(/^\d+\.\s+(.+)/)) {
            if (!inList || listType !== 'ol') {
                if (inList) {
                    result.push(listType === 'ul' ? '</ul>' : '</ol>');
                }
                result.push('<ol>');
                inList = true;
                listType = 'ol';
            }
            result.push('<li>' + line.replace(/^\d+\.\s+/, '') + '</li>');
        }
        // Regular line
        else {
            if (inList) {
                result.push(listType === 'ul' ? '</ul>' : '</ol>');
                inList = false;
                listType = null;
            }
            if (line.trim() !== '') {
                result.push(line + '<br>');
            } else {
                result.push('<br>');
            }
        }
    }

    // Close any open list
    if (inList) {
        result.push(listType === 'ul' ? '</ul>' : '</ol>');
    }

    return result.join('');
}

// Update preview panel
function updatePreview() {
    var previewContent = document.getElementById('preview-content');
    var text = content.value;
    var html = markdownToHtml(text);
    previewContent.innerHTML = html;
}

// Update preview when user types
content.addEventListener('input', updatePreview);
// Set initial preview on page load
updatePreview();

// Text formatting function for bold, italic, and lists
function formatText(format) {
    var textarea = document.getElementById('content');
    var start = textarea.selectionStart;
    var end = textarea.selectionEnd;
    var selectedText = textarea.value.substring(start, end);
    var beforeText = textarea.value.substring(0, start);
    var afterText = textarea.value.substring(end);

    var newText = '';
    var newCursorPos = 0;
    var selectionStart = 0;
    var selectionEnd = 0;

    switch (format) {
        case 'bold':
            if (selectedText.length > 0) {
                // Wrap selected text
                newText = '**' + selectedText + '**';
                textarea.value = beforeText + newText + afterText;
                newCursorPos = start + newText.length;
                textarea.setSelectionRange(newCursorPos, newCursorPos);
            } else {
                // Insert placeholder
                newText = '**bold text**';
                textarea.value = beforeText + newText + afterText;
                // Select the placeholder text "bold text"
                selectionStart = start + 2;
                selectionEnd = start + 11;
                textarea.setSelectionRange(selectionStart, selectionEnd);
            }
            break;

        case 'italic':
            if (selectedText.length > 0) {
                // Wrap selected text
                newText = '*' + selectedText + '*';
                textarea.value = beforeText + newText + afterText;
                newCursorPos = start + newText.length;
                textarea.setSelectionRange(newCursorPos, newCursorPos);
            } else {
                // Insert placeholder
                newText = '*italic text*';
                textarea.value = beforeText + newText + afterText;
                // Select the placeholder text "italic text"
                selectionStart = start + 1;
                selectionEnd = start + 12;
                textarea.setSelectionRange(selectionStart, selectionEnd);
            }
            break;

        case 'bullet':
            if (selectedText.length > 0) {
                // Add bullet to each line
                var lines = selectedText.split('\n');
                newText = lines.map(function (line) {
                    return line.trim() ? '- ' + line : line;
                }).join('\n');
            } else {
                // Start on new line if not at beginning
                var needsNewline = beforeText.length > 0 && !beforeText.endsWith('\n');
                newText = (needsNewline ? '\n' : '') + '- ';
            }
            textarea.value = beforeText + newText + afterText;
            newCursorPos = start + newText.length;
            textarea.setSelectionRange(newCursorPos, newCursorPos);
            break;

        case 'numbered':
            if (selectedText.length > 0) {
                // Add numbers to each line
                var lines = selectedText.split('\n');
                newText = lines.map(function (line, i) {
                    return line.trim() ? (i + 1) + '. ' + line : line;
                }).join('\n');
            } else {
                // Start on new line if not at beginning
                var needsNewline = beforeText.length > 0 && !beforeText.endsWith('\n');
                newText = (needsNewline ? '\n' : '') + '1. ';
            }
            textarea.value = beforeText + newText + afterText;
            newCursorPos = start + newText.length;
            textarea.setSelectionRange(newCursorPos, newCursorPos);
            break;
    }

    // Update character count
    updateCharCount();

    // Focus back on textarea
    textarea.focus();
}

// Attach click event listeners to formatting buttons
var formatButtons = document.querySelectorAll('.format-btn');

for (var i = 0; i < formatButtons.length; i++) {
    formatButtons[i].addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        var format = this.getAttribute('data-format');
        formatText(format);
        return false;
    });
}
