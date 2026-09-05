document.addEventListener("DOMContentLoaded", () => {

    // تشغيل الصفحة
    console.log("MT Character System جاهز");

    // تأثير ظهور العناصر عند تحميل الصفحة
    const elements = document.querySelectorAll(
        ".section-card, .characters-box, .character-card, .character-form"
    );

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

});
