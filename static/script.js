document.addEventListener("DOMContentLoaded", () => {

    console.log("MT Character System جاهز");

    /* =========================
       PAGE ELEMENTS
    ========================= */

    const elements = document.querySelectorAll(
        ".section-card, .characters-box, .character-card, .character-form"
    );

    /* =========================
       PAGE LOAD ANIMATION
    ========================= */

    elements.forEach((element, index) => {

        element.style.opacity = "0";
        element.style.transform = "translateY(20px)";

        setTimeout(() => {

            element.style.transition =
                "opacity 0.6s ease, transform 0.6s ease";

            element.style.opacity = "1";
            element.style.transform = "translateY(0)";

        }, index * 100);

    });

    /* =========================
       CARD HOVER EFFECT
    ========================= */

    const cards = document.querySelectorAll(".section-card");

    cards.forEach((card) => {

        card.addEventListener("mouseenter", () => {

            card.style.setProperty(
                "--mouse-x",
                "50%"
            );

            card.style.setProperty(
                "--mouse-y",
                "50%"
            );

        });

    });

    /* =========================
       FORM INPUT EFFECT
    ========================= */

    const inputs = document.querySelectorAll(
        ".character-form input"
    );

    inputs.forEach((input) => {

        input.addEventListener("focus", () => {

            input.parentElement?.classList.add(
                "input-focused"
            );

        });

        input.addEventListener("blur", () => {

            input.parentElement?.classList.remove(
                "input-focused"
            );

        });

    });

    /* =========================
       BUTTON CLICK EFFECT
    ========================= */

    const buttons = document.querySelectorAll(
        "button, .register-button, .open"
    );

    buttons.forEach((button) => {

        button.addEventListener("click", () => {

            button.classList.add("button-clicked");

            setTimeout(() => {

                button.classList.remove(
                    "button-clicked"
                );

            }, 180);

        });

    });

    /* =========================
       PREVENT DOUBLE FORM SUBMIT
    ========================= */

    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {

        form.addEventListener("submit", () => {

            const submitButton =
                form.querySelector(
                    'button[type="submit"]'
                );

            if (!submitButton) return;

            submitButton.disabled = true;

            submitButton.style.opacity = "0.65";
            submitButton.style.cursor = "wait";

            const originalText =
                submitButton.textContent;

            submitButton.textContent =
                "جاري التسجيل...";

            setTimeout(() => {

                if (submitButton.disabled) {

                    submitButton.disabled = false;

                    submitButton.style.opacity = "";
                    submitButton.style.cursor = "";

                    submitButton.textContent =
                        originalText;

                }

            }, 5000);

        });

    });

    /* =========================
       DATE INPUT
    ========================= */

    const dateInputs = document.querySelectorAll(
        'input[type="date"]'
    );

    dateInputs.forEach((input) => {

        input.addEventListener("change", () => {

            if (input.value) {

                input.classList.add(
                    "has-value"
                );

            } else {

                input.classList.remove(
                    "has-value"
                );

            }

        });

    });

    /* =========================
       ESC KEY
    ========================= */

    document.addEventListener("keydown", (event) => {

        if (event.key === "Escape") {

            document.activeElement?.blur();

        }

    });

    /* =========================
       CONSOLE
    ========================= */

    console.log(
        "MT Character System - JavaScript loaded successfully"
    );

});
