try {
    throw new TypeError("boom");
} catch (e) {
    print(e.message);
} finally {
    print("done");
}
