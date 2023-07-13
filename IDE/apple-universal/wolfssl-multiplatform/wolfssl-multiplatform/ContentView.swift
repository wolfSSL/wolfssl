//
//  ContentView.swift
//  wolfssl-multiplatform
//
//  Created by Brett Nicholas on 7/11/23.
//

import SwiftUI

struct ContentView: View {
    
    // Call our test function in the initialization of the view
    init() {
        wolfssl_test();
    }
    
    
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundColor(.accentColor)
            Text("Hello, world!")
        }
        .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
