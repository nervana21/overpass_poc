// tests/my_test.rs

use overpass_wasm::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_example() {
    let result = add_numbers(2, 3);
    assert_eq!(result, 5);

    let text = "Hello, WebAssembly!";
    let processed = process_string(text);
    assert_eq!(processed, "HELLO, WEBASSEMBLY!");

    let array = vec![1, 2, 3, 4, 5];
    let sum = sum_array(&array);
    assert_eq!(sum, 15);

    let is_valid = validate_input("test@example.com");
    assert!(is_valid);

    let computed = complex_calculation(10);
    assert!(computed > 0.0);
}
